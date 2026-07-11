#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
from pyod.models.auto_encoder import AutoEncoder
from pyod.models.iforest import IForest
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

from ids_network_common import (
    extract_numeric_keys,
    flows_from_pcap,
    load_flows,
    matrix_from_flows,
    standardize_matrix,
)


DEFAULT_MODEL_PATH = Path("/models/ids-network/autoencoder.joblib")
DEFAULT_PLOTS_DIR = Path("/plots")
FLOW_IDENTITY_KEYS = ("saddr", "daddr", "sport", "dport", "smac", "dmac", "proto")
MODEL_TYPE_CHOICES = ("autoencoder", "iforest", "random_forest", "mlp")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IDS model training and inference over pcap files using Argus + PyOD")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser(
        "train",
        help="train model from pcap files or labeled JSONL dataset files",
    )
    train_parser.add_argument(
        "--pcaps",
        nargs="*",
        default=[],
        help="paths to training pcap files",
    )
    train_parser.add_argument(
        "--labeled-datasets",
        nargs="+",
        default=[],
        help="paths to labeled JSONL dataset files for supervised training",
    )
    train_parser.add_argument(
        "--label-column",
        default="label",
        help="label field name for supervised datasets (default: label)",
    )
    train_parser.add_argument(
        "--model-path",
        dest="model_path",
        default=None,
        help="output model path (default: /models/<dataset-stem>/<model-type>.joblib)",
    )
    train_parser.add_argument(
        "--model-type",
        choices=MODEL_TYPE_CHOICES,
        default=os.environ.get("IDS_NETWORK_MODEL_TYPE", "random_forest").strip().lower(),
        help="model architecture to train (default: autoencoder)",
    )

    infer_parser = subparsers.add_parser("infer", help="run inference against one or more pcap files")
    infer_parser.add_argument("pcaps", nargs="+", help="paths to pcap files for scoring")
    infer_parser.add_argument("--model-path", dest="model_path", default=str(DEFAULT_MODEL_PATH), help="trained model path")
    infer_parser.add_argument(
        "--decision-threshold",
        type=float,
        default=None,
        help="decision score threshold (if omitted, anomaly labels come from model.predict)",
    )
    infer_parser.add_argument(
        "--plot-scores-hist",
        action="store_true",
        help="generate a histogram plot of decision scores and save it to --plots-dir",
    )
    infer_parser.add_argument(
        "--plots-dir",
        default=str(DEFAULT_PLOTS_DIR),
        help="directory to save score histogram plots (default: /plots)",
    )

    return parser.parse_args()


def build_model(sample_count: int, model_type: str):
    if model_type == "iforest":
        return IForest()
    if model_type == "random_forest":
        return RandomForestClassifier(n_estimators=100, random_state=42)
    if model_type == "mlp":
        return MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, random_state=42)
    batch_size = max(1, min(32, sample_count))
    return AutoEncoder(batch_size=batch_size, verbose=1)


def default_model_path(data_paths: list[Path], model_type: str) -> Path:
    if not data_paths:
        dataset_dir = "dataset"
    else:
        first_stem = data_paths[0].stem
        if len(data_paths) == 1:
            dataset_dir = first_stem
        else:
            dataset_dir = f"{first_stem}_plus_{len(data_paths) - 1}"
    return Path("/models/ids-network") / dataset_dir / f"{model_type}.joblib"


def load_labeled_dataset(dataset_paths: list[Path], label_column: str) -> tuple[list[dict], np.ndarray, dict[str, int]]:
    """Load labeled JSONL dataset files for supervised training."""
    all_flows: list[dict] = []
    all_labels: list[str] = []

    for path in dataset_paths:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"labeled dataset not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if label_column not in record:
                    raise ValueError(f"missing label column '{label_column}' in {path}")
                label = record[label_column]
                if label is None or label == "":
                    raise ValueError(f"empty label for record in {path}")
                all_labels.append(str(label))
                all_flows.append(record)

    if not all_flows:
        raise ValueError("no labeled records found in dataset paths")

    unique_labels = list(dict.fromkeys(all_labels))
    if len(unique_labels) != 2:
        raise ValueError("supervised training requires exactly two label values")

    lower_labels = {label.lower(): label for label in unique_labels}
    if "normal" in lower_labels and "attack" in lower_labels:
        label_map = {"normal": 0, "attack": 1}
    elif unique_labels[0].lower() == "normal":
        label_map = {unique_labels[0]: 0, unique_labels[1]: 1}
    elif unique_labels[1].lower() == "normal":
        label_map = {unique_labels[1]: 0, unique_labels[0]: 1}
    else:
        label_map = {unique_labels[0]: 0, unique_labels[1]: 1}

    y = np.asarray([label_map[label] for label in all_labels], dtype=np.int64)
    return all_flows, y, label_map


def _model_scores(model: object, matrix: np.ndarray) -> np.ndarray:
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(matrix), dtype=np.float64)
    if hasattr(model, "predict_proba"):
        proba = np.asarray(model.predict_proba(matrix), dtype=np.float64)
        if proba.ndim == 1:
            return proba
        if hasattr(model, "classes_") and 1 in model.classes_:
            positive_class_index = list(model.classes_).index(1)
        else:
            positive_class_index = min(1, proba.shape[1] - 1)
        return proba[:, positive_class_index]
    raise RuntimeError("model does not support scoring")


def train_model(
    pcap_paths: list[Path],
    labeled_dataset_paths: list[Path],
    label_column: str,
    model_path: Path,
    model_type: str,
) -> None:
    if not pcap_paths and not labeled_dataset_paths:
        raise SystemExit("must provide at least one of: --pcaps or --labeled-datasets")
    if labeled_dataset_paths:
        flows, labels, label_map = load_labeled_dataset(labeled_dataset_paths, label_column)
        numeric_keys = extract_numeric_keys(flows)
        matrix = matrix_from_flows(flows, numeric_keys)
        if matrix.size == 0:
            raise SystemExit("no numeric flow features extracted from labeled dataset")

        # Randomly undersample majority class for supervised training
        class_0_mask = labels == 0
        class_1_mask = labels == 1
        class_0_count = int(np.sum(class_0_mask))
        class_1_count = int(np.sum(class_1_mask))
        print(f"before undersampling: normal={class_0_count}, attack={class_1_count}", flush=True)

        if class_0_count > class_1_count:
            # Undersample normal (class 0) to match attack (class 1)
            undersample_indices = np.random.choice(
                np.where(class_0_mask)[0],
                size=class_1_count,
                replace=False,
            )
            keep_mask = np.zeros(len(labels), dtype=bool)
            keep_mask[undersample_indices] = True
            keep_mask[class_1_mask] = True
        elif class_1_count > class_0_count:
            # Undersample attack (class 1) to match normal (class_0)
            undersample_indices = np.random.choice(
                np.where(class_1_mask)[0],
                size=class_0_count,
                replace=False,
            )
            keep_mask = np.zeros(len(labels), dtype=bool)
            keep_mask[class_0_mask] = True
            keep_mask[undersample_indices] = True
        else:
            # Balanced, no undersampling needed
            keep_mask = np.ones(len(labels), dtype=bool)

        matrix = matrix[keep_mask]
        labels = labels[keep_mask]

        new_class_0_count = int(np.sum(labels == 0))
        new_class_1_count = int(np.sum(labels == 1))
        print(f"after undersampling: normal={new_class_0_count}, attack={new_class_1_count}", flush=True)

        matrix, feature_mean, feature_std = standardize_matrix(matrix)
        model = build_model(int(matrix.shape[0]), model_type)
        print(f"starting supervised {model_type} training on {matrix.shape[0]} samples...", flush=True)
        if model_type in {"random_forest", "mlp"}:
            model.fit(matrix, labels)
        else:
            model.fit(matrix)
        train_scores = _model_scores(model, matrix)
    else:
        all_flows = load_flows(pcap_paths)
        numeric_keys = extract_numeric_keys(all_flows)
        matrix = matrix_from_flows(all_flows, numeric_keys)

        if matrix.size == 0:
            raise SystemExit("no numeric flow features extracted from training pcaps")

        matrix, feature_mean, feature_std = standardize_matrix(matrix)
        model = build_model(int(matrix.shape[0]), model_type)
        print(f"starting unsupervised {model_type} training on {matrix.shape[0]} samples...", flush=True)
        model.fit(matrix)
        train_scores = _model_scores(model, matrix)
        label_map = {}

    model_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "model_type": model_type,
        "feature_keys": numeric_keys,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "label_column": label_column,
        "label_map": label_map,
        "train_score_min": float(np.min(train_scores)),
        "train_score_max": float(np.max(train_scores)),
        "train_score_mean": float(np.mean(train_scores)),
        "train_score_std": float(np.std(train_scores)),
        "trained_flows": int(matrix.shape[0]),
        "trained_features": int(matrix.shape[1]),
    }
    joblib.dump(payload, model_path)

    print(f"saved {model_type} model to {model_path}")
    print(f"trained on {matrix.shape[0]} flows with {matrix.shape[1]} features")


def save_score_histogram(
    scores: np.ndarray,
    pcap: Path,
    model_type: str,
    plots_dir: Path,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plots_dir.mkdir(parents=True, exist_ok=True)
    output_path = plots_dir / f"{pcap.stem}_{model_type}_scores_hist.png"

    plt.figure(figsize=(8, 4.5))
    plt.hist(scores, alpha=0.85)
    plt.title(f"Decision Score Histogram: {pcap.name}")
    plt.xlabel("decision_function score")
    plt.ylabel("count")
    plt.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    return output_path


def infer_model(
    pcap_paths: list[Path],
    model_path: Path,
    decision_threshold: float | None = None,
    plot_scores_hist: bool = False,
    plots_dir: Path = DEFAULT_PLOTS_DIR,
) -> None:
    context = load_live_inference_context(model_path, decision_threshold)
    model = context["model"]
    model_type = context["model_type"]
    feature_keys: list[str] | None = context["feature_keys"]
    feature_mean = context["feature_mean"]
    feature_std = context["feature_std"]
    threshold = context["threshold"]

    for pcap in pcap_paths:
        flows = flows_from_pcap(pcap)
        keys = feature_keys or extract_numeric_keys(flows)
        matrix = matrix_from_flows(flows, keys)
        if matrix.size == 0:
            print(json.dumps({"pcap": str(pcap), "flows": 0, "anomalies": 0, "note": "no numeric features"}))
            continue

        matrix, _, _ = standardize_matrix(matrix, mean=feature_mean, std=feature_std)

        scores = None
        if threshold is not None or plot_scores_hist:
            scores = _model_scores(model, matrix)

        if threshold is None:
            preds = model.predict(matrix)
            anomalies = int(np.sum(preds == 1))
            max_score = None
            min_score = None
            mean_score = None
            std_score = None
        else:
            assert scores is not None
            anomalies = int(np.sum(scores > threshold))
            max_score = float(np.max(scores))
            min_score = float(np.min(scores))
            mean_score = float(np.mean(scores))
            std_score = float(np.std(scores))
        total = int(matrix.shape[0])

        result = {
            "pcap": str(pcap),
            "model_type": model_type,
            "flows": total,
            "anomalies": anomalies,
            "anomaly_ratio": float(anomalies / total) if total else 0.0,
            "decision_threshold": threshold,
        }
        if max_score is not None and min_score is not None:
            result["max_score"] = max_score
            result["min_score"] = min_score
        if mean_score is not None and std_score is not None:
            result["mean_score"] = mean_score
            result["std_score"] = std_score
        if plot_scores_hist and scores is not None:
            hist_path = save_score_histogram(scores, pcap, model_type, plots_dir)
            result["score_histogram"] = str(hist_path)

        print(
            json.dumps(result, sort_keys=True)
        )


def load_live_inference_context(
    model_path: Path,
    decision_threshold: float | None = None,
) -> Dict[str, Any]:
    """Load model payload and normalize runtime scoring parameters."""
    payload = joblib.load(model_path)
    return {
        "model": payload["model"],
        "model_type": payload.get("model_type", "unknown"),
        "feature_keys": payload.get("feature_keys"),
        "feature_mean": payload.get("feature_mean"),
        "feature_std": payload.get("feature_std"),
        "threshold": float(decision_threshold) if decision_threshold is not None else None,
    }


def score_live_flow(
    flow: Dict[str, Any],
    flow_index: int,
    interface: str,
    context: Dict[str, Any],
) -> Dict[str, Any] | None:
    """Score one flow and return a normalized result; return None when unusable."""
    feature_keys: list[str] | None = context["feature_keys"]
    keys = feature_keys or extract_numeric_keys([flow])
    matrix = matrix_from_flows([flow], keys)
    if matrix.size == 0:
        return None

    matrix, _, _ = standardize_matrix(
        matrix,
        mean=context["feature_mean"],
        std=context["feature_std"],
    )

    score = float(_model_scores(context["model"], matrix)[0])
    if not np.isfinite(score):
        return None
    threshold = context["threshold"]
    if threshold is None:
        pred = context["model"].predict(matrix)
        is_anomaly = bool(int(pred[0]) == 1)
    else:
        is_anomaly = bool(score > threshold)

    result = {
        "source_interface": interface,
        "model_type": context["model_type"],
        "flow_index": flow_index,
        "anomaly": is_anomaly,
        "decision_threshold": threshold,
        "score": score,
        "raw": dict(flow),
    }
    for key in FLOW_IDENTITY_KEYS:
        value = flow.get(key)
        if value not in (None, ""):
            result[key] = value

    return result



def main() -> int:
    args = parse_args()

    if args.command == "train":
        pcap_paths = [Path(p) for p in args.pcaps]
        labeled_paths = [Path(p) for p in args.labeled_datasets]
        data_paths = labeled_paths if labeled_paths else pcap_paths
        model_path = Path(args.model_path) if args.model_path else default_model_path(data_paths, args.model_type)
        train_model(
            pcap_paths=pcap_paths,
            labeled_dataset_paths=labeled_paths,
            label_column=args.label_column,
            model_path=model_path,
            model_type=args.model_type,
        )
        return 0

    if args.command == "infer":
        infer_model(
            [Path(p) for p in args.pcaps],
            Path(args.model_path),
            decision_threshold=args.decision_threshold,
            plot_scores_hist=args.plot_scores_hist,
            plots_dir=Path(args.plots_dir),
        )
        return 0

    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
