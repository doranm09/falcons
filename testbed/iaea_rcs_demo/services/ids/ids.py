#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from pyod.models.iforest import IForest
from pyod.models.vae import VAE

from ids_common import (
    extract_numeric_keys,
    flows_from_pcap,
    iter_flows_from_interface,
    load_flows,
    matrix_from_flows,
    standardize_matrix,
)


DEFAULT_MODEL_PATH = Path("/models/iforest.joblib")
DEFAULT_PLOTS_DIR = Path("/plots")
FLOW_IDENTITY_KEYS = ("src_ip", "dst_ip", "src_port", "dst_port", "src_mac", "dst_mac", "protocol")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IDS training and inference over pcap files using NFStream, optional Argus live capture, and PyOD"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="train model from one or more pcap files")
    train_parser.add_argument("pcaps", nargs="+", help="paths to training pcap files")
    train_parser.add_argument(
        "--model",
        default=None,
        help="output model path (default: /models/<pcap-stem>/<model-type>.joblib)",
    )
    train_parser.add_argument(
        "--model-type",
        choices=("iforest", "vae"),
        default="iforest",
        help="model family to train (default: iforest)",
    )

    infer_parser = subparsers.add_parser("infer", help="run inference against one or more pcap files")
    infer_parser.add_argument("pcaps", nargs="+", help="paths to pcap files for scoring")
    infer_parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="trained model path")
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

    watch_parser = subparsers.add_parser("watch", help="capture live traffic from an interface and score flows")
    watch_parser.add_argument("--iface", required=True, help="network interface to capture traffic from")
    watch_parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="trained model path")
    watch_parser.add_argument(
        "--decision-threshold",
        type=float,
        default=None,
        help="decision score threshold (if omitted, anomaly labels come from model.predict)",
    )
    watch_parser.add_argument(
        "--idle-timeout",
        type=int,
        default=1,
        help="NFStream idle flow timeout in seconds when IDS_INTERFACE_BACKEND=nfstream (default: 1)",
    )
    watch_parser.add_argument(
        "--active-timeout",
        type=int,
        default=1,
        help="NFStream active flow timeout in seconds when IDS_INTERFACE_BACKEND=nfstream (default: 1)",
    )

    return parser.parse_args()


def build_model(model_type: str, sample_count: int):
    if model_type == "iforest":
        return IForest(random_state=42)
    if model_type == "vae":
        batch_size = max(1, min(32, sample_count))
        return VAE(batch_size=batch_size)
    raise SystemExit(f"unsupported model type: {model_type}")


def default_model_path(pcap_paths: list[Path], model_type: str) -> Path:
    first_stem = pcap_paths[0].stem
    if len(pcap_paths) == 1:
        dataset_dir = first_stem
    else:
        dataset_dir = f"{first_stem}_plus_{len(pcap_paths) - 1}"
    return Path("/models") / dataset_dir / f"{model_type}.joblib"


def train_model(
    pcap_paths: list[Path],
    model_path: Path,
    model_type: str,
) -> None:
    all_flows = load_flows(pcap_paths)
    numeric_keys = extract_numeric_keys(all_flows)
    matrix = matrix_from_flows(all_flows, numeric_keys)

    if matrix.size == 0:
        raise SystemExit("no numeric flow features extracted from training pcaps")

    matrix, feature_mean, feature_std = standardize_matrix(matrix)

    model = build_model(model_type, int(matrix.shape[0]))
    model.fit(matrix)
    train_scores = model.decision_function(matrix)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "model_type": model_type,
        "feature_keys": numeric_keys,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
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
    payload = joblib.load(model_path)
    model = payload["model"]
    model_type = payload.get("model_type", "unknown")
    feature_keys: list[str] | None = payload.get("feature_keys")
    feature_mean = payload.get("feature_mean")
    feature_std = payload.get("feature_std")
    train_score_mean = payload.get("train_score_mean")
    train_score_std = payload.get("train_score_std")
    threshold = float(decision_threshold) if decision_threshold is not None else None

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
            scores = model.decision_function(matrix)

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
        if train_score_mean is not None and train_score_std is not None:
            result["train_score_mean"] = float(train_score_mean)
            result["train_score_std"] = float(train_score_std)
        if plot_scores_hist and scores is not None:
            hist_path = save_score_histogram(scores, pcap, model_type, plots_dir)
            result["score_histogram"] = str(hist_path)

        print(json.dumps(result, sort_keys=True))


def load_live_inference_context(
    model_path: Path,
    decision_threshold: float | None = None,
) -> dict[str, Any]:
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
    flow: dict[str, Any],
    flow_index: int,
    interface: str,
    context: dict[str, Any],
) -> dict[str, Any] | None:
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

    score = float(context["model"].decision_function(matrix)[0])
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


def watch_interface(
    interface: str,
    model_path: Path,
    decision_threshold: float | None = None,
    idle_timeout: int = 1,
    active_timeout: int = 1,
) -> None:
    context = load_live_inference_context(model_path, decision_threshold)

    print(
        f"watching interface {interface} for live flows "
        f"(idle_timeout={idle_timeout}s, active_timeout={active_timeout}s)"
    )
    for index, flow in enumerate(
        iter_flows_from_interface(interface, idle_timeout=idle_timeout, active_timeout=active_timeout),
        start=1,
    ):
        result = score_live_flow(flow, index, interface, context)
        if result is None:
            continue

        print(json.dumps(result, sort_keys=True), flush=True)


def main() -> int:
    args = parse_args()

    if args.command == "train":
        pcap_paths = [Path(p) for p in args.pcaps]
        model_path = Path(args.model) if args.model else default_model_path(pcap_paths, args.model_type)
        train_model(
            pcap_paths=pcap_paths,
            model_path=model_path,
            model_type=args.model_type,
        )
        return 0

    if args.command == "infer":
        infer_model(
            [Path(p) for p in args.pcaps],
            Path(args.model),
            decision_threshold=args.decision_threshold,
            plot_scores_hist=args.plot_scores_hist,
            plots_dir=Path(args.plots_dir),
        )
        return 0

    if args.command == "watch":
        watch_interface(
            args.iface,
            Path(args.model),
            decision_threshold=args.decision_threshold,
            idle_timeout=args.idle_timeout,
            active_timeout=args.active_timeout,
        )
        return 0

    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
