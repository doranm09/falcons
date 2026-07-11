#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict
from urllib import request

import joblib
import numpy as np
from influxdb_client import InfluxDBClient
from pyod.models.auto_encoder import AutoEncoder
from pyod.models.iforest import IForest


DEFAULT_MODEL_PATH = Path("/models/ids-process/autoencoder.joblib")
MODEL_TYPE_CHOICES = ("autoencoder", "iforest")
DEFAULT_MAIN_TAG_KEYS = (
    "average_pressure",
    "health_code",
    "bridge_online",
    "bridge_poll_errors",
    "bridge_write_errors",
    "bridge_active_overrides",
    "hv_owner",
    "hv_applied",
    "pvb_owner",
    "pvb_applied",
    "pvc_owner",
    "pvc_applied",
    "heat_owner",
    "heat_applied",
    "pt455",
    "pt456",
    "pt457",
)


def _default_threshold_from_env() -> float | None:
    raw = os.environ.get("IDS_PROCESS_DECISION_THRESHOLD", "10")
    if raw in {"", "none", "None"}:
        return None
    return float(raw)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Process-variable IDS model training and inference over historian samples"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_influx_options(target: argparse.ArgumentParser) -> None:
        target.add_argument("--influx-url", default=os.environ.get("INFLUX_URL", ""))
        target.add_argument("--influx-token", default=os.environ.get("INFLUX_TOKEN", "iaea-historian-token"))
        target.add_argument("--influx-org", default=os.environ.get("INFLUX_ORG", "iaea"))
        target.add_argument("--influx-bucket", default=os.environ.get("INFLUX_BUCKET", "iaea_rcs"))
        target.add_argument("--profile", default=os.environ.get("IDS_PROCESS_PROFILE", "main"))
        target.add_argument("--measurement", default=os.environ.get("IDS_PROCESS_MEASUREMENT", "rcs_metrics"))
        target.add_argument("--tag-keys", default=os.environ.get("IDS_PROCESS_TAG_KEYS", ""))

    train_parser = subparsers.add_parser("train", help="train autoencoder from historian process samples")
    add_influx_options(train_parser)
    train_parser.add_argument("--range-start", default=os.environ.get("IDS_PROCESS_TRAIN_RANGE_START", "-5m"))
    train_parser.add_argument(
        "--jsonl-path",
        dest="jsonl_path",
        type=Path,
        default=Path(os.environ.get("IDS_PROCESS_JSONL_PATH", "")) or None,
        help="path to JSONL file for training (optional, overrides InfluxDB)",
    )
    train_parser.add_argument(
        "--historian-status-url",
        dest="historian_status_url",
        default=os.environ.get("IDS_PROCESS_HISTORIAN_STATUS_URL", "http://historian:4840/"),
        help="historian status endpoint URL for live training data collection",
    )
    train_parser.add_argument(
        "--training-duration",
        dest="training_duration",
        type=float,
        default=float(os.environ.get("IDS_PROCESS_TRAINING_DURATION", "30.0")),
        help="training data collection duration in seconds (default: 30.0)",
    )
    train_parser.add_argument(
        "--model-path",
        dest="model_path",
        type=Path,
        default=Path(os.environ.get("IDS_PROCESS_MODEL_PATH", str(DEFAULT_MODEL_PATH))),
    )
    train_parser.add_argument(
        "--model-type",
        choices=MODEL_TYPE_CHOICES,
        default=os.environ.get("IDS_PROCESS_MODEL_TYPE", "autoencoder").strip().lower(),
        help="model architecture to train (default: autoencoder)",
    )

    infer_parser = subparsers.add_parser("infer", help="score historian samples from InfluxDB")
    add_influx_options(infer_parser)
    infer_parser.add_argument("--range-start", default=os.environ.get("IDS_PROCESS_INFER_RANGE_START", "-2h"))
    infer_parser.add_argument(
        "--model-path",
        dest="model_path",
        type=Path,
        default=Path(os.environ.get("IDS_PROCESS_MODEL_PATH", str(DEFAULT_MODEL_PATH))),
    )
    infer_parser.add_argument(
        "--decision-threshold",
        type=float,
        default=_default_threshold_from_env(),
    )

    return parser.parse_args()


def _parse_tag_keys(raw: str | None) -> list[str]:
    candidate = raw if raw is not None else os.environ.get("IDS_PROCESS_TAG_KEYS", "")
    if not candidate.strip():
        return list(DEFAULT_MAIN_TAG_KEYS)
    return [item.strip() for item in candidate.split(",") if item.strip()]


def _coerce_numeric_or_zero(value: Any) -> float:
    if value is None or isinstance(value, bool):
        return 0.0
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not np.isfinite(numeric):
        return 0.0
    return numeric


def _query_rows(
    query_api,
    bucket: str,
    org: str,
    measurement: str,
    profile: str,
    tag_keys: list[str],
    *,
    range_expr: str,
    limit: int | None,
    desc: bool,
) -> list[Dict[str, Any]]:
    columns = ["_time"] + tag_keys
    flux_columns = json.dumps(columns)
    flux = (
        f'from(bucket: "{bucket}")\n'
        f"  |> range(start: {range_expr})\n"
        f'  |> filter(fn: (r) => r._measurement == "{measurement}" and r.profile == "{profile}")\n'
        f'  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")\n'
        f'  |> keep(columns: {flux_columns})\n'
        f'  |> sort(columns: ["_time"], desc: {"true" if desc else "false"})\n'
    )
    if limit is not None:
        flux += f"  |> limit(n: {limit})\n"

    tables = query_api.query(org=org, query=flux)
    rows: list[Dict[str, Any]] = []
    for table in tables:
        for record in table.records:
            rows.append(dict(record.values))
    return rows


def _matrix_from_rows(rows: list[Dict[str, Any]], feature_keys: list[str]) -> np.ndarray:
    if not rows or not feature_keys:
        return np.empty((0, 0), dtype=np.float64)
    matrix: list[list[float]] = []
    for row in rows:
        matrix.append([_coerce_numeric_or_zero(row.get(key)) for key in feature_keys])
    return np.asarray(matrix, dtype=np.float64)


def _matrix_from_jsonl(records: list[Dict[str, Any]], feature_keys: list[str]) -> np.ndarray:
    """Build matrix from JSONL records where each record has a 'fields' dict."""
    if not records or not feature_keys:
        return np.empty((0, 0), dtype=np.float64)
    matrix: list[list[float]] = []
    for record in records:
        fields = record.get("fields", {})
        matrix.append([_coerce_numeric_or_zero(fields.get(key)) for key in feature_keys])
    return np.asarray(matrix, dtype=np.float64)


def _standardize_matrix(
    matrix: np.ndarray,
    mean: np.ndarray | None = None,
    std: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    eps = 1e-9
    if matrix.size == 0:
        empty = np.empty((0,), dtype=np.float64)
        return matrix.astype(np.float64, copy=False), empty, empty

    if mean is None:
        mean = np.mean(matrix, axis=0)
    else:
        mean = np.asarray(mean, dtype=np.float64)
    if std is None:
        std = np.std(matrix, axis=0)
    else:
        std = np.asarray(std, dtype=np.float64)

    standardized = (matrix - mean) / (std + eps)
    standardized = np.nan_to_num(standardized, nan=0.0, posinf=0.0, neginf=0.0)
    return standardized.astype(np.float64, copy=False), mean, std


def _build_model(sample_count: int, model_type: str):
    if model_type == "iforest":
        return IForest()
    batch_size = max(1, min(32, sample_count))
    return AutoEncoder(batch_size=batch_size, verbose=1)


def _load_live_inference_context(
    model_path: Path,
    decision_threshold: float | None,
) -> Dict[str, Any]:
    payload = joblib.load(model_path)
    return {
        "model": payload["model"],
        "feature_keys": payload["feature_keys"],
        "feature_mean": payload.get("feature_mean"),
        "feature_std": payload.get("feature_std"),
        "threshold": float(decision_threshold) if decision_threshold is not None else None,
    }


def _score_row(row: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    feature_keys: list[str] = context["feature_keys"]
    matrix = _matrix_from_rows([row], feature_keys)
    matrix, _, _ = _standardize_matrix(
        matrix,
        mean=context["feature_mean"],
        std=context["feature_std"],
    )

    score = float(context["model"].decision_function(matrix)[0])
    # Clip score to prevent Infinity/NaN from breaking UI display
    score = np.clip(score, 0.0, 1e6)
    score = np.nan_to_num(score, nan=0.0, posinf=1e6, neginf=0.0)
    score = float(score)
    
    threshold = context["threshold"]
    if threshold is None:
        pred = context["model"].predict(matrix)
        anomaly = bool(int(pred[0]) == 1)
    else:
        anomaly = bool(score > threshold)

    return {
        "anomaly": anomaly,
        "score": score,
        "decision_threshold": threshold,
    }


def load_jsonl_data(jsonl_path: Path) -> list[dict]:
    """Load JSONL file and return list of dictionaries."""
    if not jsonl_path.exists():
        raise FileNotFoundError(f"JSONL file not found: {jsonl_path}")
    
    records = []
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                records.append(record)
            except json.JSONDecodeError as e:
                print(f"Warning: skipping line {line_num}: {e}")
    
    return records


def train_from_influx(args: argparse.Namespace) -> int:
    feature_keys = _parse_tag_keys(args.tag_keys)
    with InfluxDBClient(url=args.influx_url, token=args.influx_token, org=args.influx_org) as client:
        rows = _query_rows(
            client.query_api(),
            args.influx_bucket,
            args.influx_org,
            args.measurement,
            args.profile,
            feature_keys,
            range_expr=args.range_start,
            limit=None,
            desc=False,
        )

    matrix = _matrix_from_rows(rows, feature_keys)
    if matrix.size == 0:
        raise SystemExit("no historian samples available for training")

    matrix, feature_mean, feature_std = _standardize_matrix(matrix)
    model = _build_model(int(matrix.shape[0]), args.model_type)
    print(f"training {args.model_type} on {matrix.shape[0]} process samples...", flush=True)
    model.fit(matrix)
    scores = model.decision_function(matrix)

    payload = {
        "model": model,
        "model_type": args.model_type,
        "feature_keys": feature_keys,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "train_score_min": float(np.min(scores)),
        "train_score_max": float(np.max(scores)),
        "train_score_mean": float(np.mean(scores)),
        "train_score_std": float(np.std(scores)),
        "trained_samples": int(matrix.shape[0]),
        "trained_features": int(matrix.shape[1]),
    }
    args.model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, args.model_path)
    print(f"saved model to {args.model_path}")
    return 0


def train_from_historian_status(args: argparse.Namespace) -> int:
    """Train model by directly sampling from historian status HTTP endpoint."""
    feature_keys = _parse_tag_keys(args.tag_keys)
    if not feature_keys:
        feature_keys = ["average_pressure"]  # Default feature
    
    print(f"[*] Training from historian status endpoint: {args.historian_status_url}")
    print(f"[*] Duration: {args.training_duration}s")
    print(f"[*] Features: {feature_keys}")
    print(f"[*] Collecting samples...", flush=True)
    
    records = []
    start_time = time.monotonic()
    last_error_time = time.monotonic()
    max_error_time = 30.0  # Stop if no data for 30 seconds
    
    while time.monotonic() - start_time < args.training_duration:
        try:
            with request.urlopen(args.historian_status_url, timeout=5.0) as response:
                payload = json.load(response)
                if not isinstance(payload, dict):
                    continue
                
                profiles = payload.get("profiles", {})
                profile_data = profiles.get(args.profile, {})
                if not profile_data.get("connected"):
                    continue
                
                values = profile_data.get("values", {})
                if not values:
                    continue
                
                # Create a record with fields dict structure
                record = {"fields": {k: values.get(k) for k in feature_keys if k in values}}
                if record["fields"]:
                    records.append(record)
                    if len(records) % 100 == 0:
                        print(f"[*] Collected {len(records)} samples...", flush=True)
                    last_error_time = time.monotonic()
                
        except Exception as e:
            error_msg = f"Error fetching status: {e}"
            if time.monotonic() - last_error_time > 3.0:
                print(f"[!] {error_msg}", file=sys.stderr, flush=True)
            last_error_time = time.monotonic()
        
        time.sleep(0.1)  # Poll every 100ms
    
    if not records:
        raise SystemExit(f"no samples collected from {args.historian_status_url}")
    
    print(f"\n[+] Collected {len(records)} samples", flush=True)
    
    # Build matrix from records
    matrix = _matrix_from_jsonl(records, feature_keys)
    if matrix.size == 0:
        raise SystemExit("no valid samples in collected data")
    
    print(f"[*] Matrix shape: {matrix.shape}", flush=True)
    
    # Compute statistics
    matrix, feature_mean, feature_std = _standardize_matrix(matrix)
    model = _build_model(int(matrix.shape[0]), args.model_type)
    print(f"[*] Training {args.model_type} on {matrix.shape[0]} process samples...", flush=True)
    model.fit(matrix)
    scores = model.decision_function(matrix)
    
    payload = {
        "model": model,
        "model_type": args.model_type,
        "feature_keys": feature_keys,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "train_score_min": float(np.min(scores)),
        "train_score_max": float(np.max(scores)),
        "train_score_mean": float(np.mean(scores)),
        "train_score_std": float(np.std(scores)),
        "trained_samples": int(matrix.shape[0]),
        "trained_features": int(matrix.shape[1]),
    }
    
    model_path = Path(args.model_path) if not isinstance(args.model_path, Path) else args.model_path
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, model_path)
    print(f"[+] Saved model to {model_path}", flush=True)
    
    # Print summary
    print(f"\n[+] Training data summary:")
    avg_pressures = [r["fields"]["average_pressure"] for r in records if "average_pressure" in r["fields"]]
    if avg_pressures:
        print(f"    Average pressure range: {min(avg_pressures)} - {max(avg_pressures)}")
        print(f"    Average pressure mean: {np.mean(avg_pressures):.2f}")
    print(f"    Training score range: {np.min(scores):.2f} - {np.max(scores):.2f}")
    print(f"    Training score mean: {np.mean(scores):.2f}")
    
    return 0


def train_from_jsonl(args: argparse.Namespace) -> int:
    if not args.jsonl_path:
        raise ValueError("--jsonl-path required for JSONL training")
    
    feature_keys = _parse_tag_keys(args.tag_keys)
    if not feature_keys:
        feature_keys = ["average_pressure"]  # Default feature
    
    print(f"Loading JSONL file: {args.jsonl_path}")
    records = load_jsonl_data(args.jsonl_path)
    
    if not records:
        raise SystemExit(f"no records found in {args.jsonl_path}")
    
    print(f"Loaded {len(records)} records from JSONL")
    
    # Build matrix from JSONL records
    matrix = _matrix_from_jsonl(records, feature_keys)
    if matrix.size == 0:
        raise SystemExit("no valid samples in JSONL data")
    
    print(f"Matrix shape: {matrix.shape}, Features: {feature_keys}")
    
    # Compute statistics
    matrix, feature_mean, feature_std = _standardize_matrix(matrix)
    model = _build_model(int(matrix.shape[0]), args.model_type)
    print(f"training {args.model_type} on {matrix.shape[0]} process samples...", flush=True)
    model.fit(matrix)
    scores = model.decision_function(matrix)
    
    payload = {
        "model": model,
        "model_type": args.model_type,
        "feature_keys": feature_keys,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "train_score_min": float(np.min(scores)),
        "train_score_max": float(np.max(scores)),
        "train_score_mean": float(np.mean(scores)),
        "train_score_std": float(np.std(scores)),
        "trained_samples": int(matrix.shape[0]),
        "trained_features": int(matrix.shape[1]),
    }
    
    args.model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, args.model_path)
    print(f"saved model to {args.model_path}")
    
    # Print summary of training data
    print(f"\nTraining data summary:")
    print(f"  Average pressure range: {min(records, key=lambda r: r['fields']['average_pressure'])['fields']['average_pressure']}-"
          f"{max(records, key=lambda r: r['fields']['average_pressure'])['fields']['average_pressure']}")
    
    return 0


def infer_from_influx(args: argparse.Namespace) -> int:
    context = _load_live_inference_context(args.model_path, args.decision_threshold)
    feature_keys: list[str] = context["feature_keys"]
    with InfluxDBClient(url=args.influx_url, token=args.influx_token, org=args.influx_org) as client:
        rows = _query_rows(
            client.query_api(),
            args.influx_bucket,
            args.influx_org,
            args.measurement,
            args.profile,
            feature_keys,
            range_expr=args.range_start,
            limit=None,
            desc=False,
        )

    if not rows:
        print(json.dumps({"samples": 0, "anomalies": 0}))
        return 0

    anomalies = 0
    for row in rows:
        scored = _score_row(row, context)
        if scored["anomaly"]:
            anomalies += 1

    result = {
        "samples": len(rows),
        "anomalies": anomalies,
        "anomaly_ratio": float(anomalies / len(rows)),
        "decision_threshold": context["threshold"],
    }
    print(json.dumps(result, sort_keys=True))
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "train":
        # Train from JSONL file if explicitly provided (not the default "./")
        if args.jsonl_path and args.jsonl_path != Path("."):
            return train_from_jsonl(args)
        # Train from historian status if INFLUX_URL is empty or explicitly set
        influx_url = os.environ.get("INFLUX_URL", "").strip()
        if not influx_url:
            return train_from_historian_status(args)
        return train_from_influx(args)
    if args.command == "infer":
        return infer_from_influx(args)
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
