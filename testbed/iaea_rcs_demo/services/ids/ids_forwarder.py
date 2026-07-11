#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib import error, request

from ids import load_live_inference_context, score_live_flow
from ids_common import iter_flows_from_interface


DEFAULT_PIPELINE_URL = "http://host.docker.internal:8000/dashboard/siem/pipeline/ingest/"
WEBAPP_FIELD_MAP = {
    "src_ip": "saddr",
    "dst_ip": "daddr",
    "src_port": "sport",
    "dst_port": "dport",
    "src_mac": "smac",
    "dst_mac": "dmac",
    "protocol": "proto",
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _build_event(flow: Dict[str, Any]) -> Dict[str, Any]:
    anomaly = bool(flow.get("anomaly", False))
    score = flow.get("score")
    threshold = flow.get("decision_threshold")

    return {
        "source": "ids",
        "event_type": "ids.anomaly" if anomaly else "ids.flow",
        "timestamp": _iso_now(),
        "score": score,
        "decision_threshold": threshold,
        "raw": flow,
    }


def normalize_to_webapp(record: Dict[str, Any]) -> Dict[str, Any]:
    """Project canonical IDS identity keys into web-app schema keys."""
    normalized = dict(record)
    for out_key, source_key in WEBAPP_FIELD_MAP.items():
        value = normalized.get(source_key)
        if value not in (None, ""):
            normalized[out_key] = value
    return normalized


def _post_json(url: str, payload: Dict[str, Any], token: str) -> None:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-SIEM-Token"] = token

    req = request.Request(url=url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=3) as response:
        if response.status >= 400:
            raise RuntimeError(f"SIEM ingest failed with status {response.status}")


def iter_scored_interface_flows(
    interface: str,
    model_path: Path,
    decision_threshold: float | None = None,
):
    """Yield scored flow dictionaries for a live interface stream."""
    context = load_live_inference_context(model_path, decision_threshold)
    for index, flow in enumerate(iter_flows_from_interface(interface), start=1):
        result = score_live_flow(flow, index, interface, context)
        if result is not None:
            yield result


def main() -> int:
    pipeline_url = os.environ.get("SIEM_PIPELINE_URL", DEFAULT_PIPELINE_URL)
    siem_token = os.environ.get("SIEM_INGEST_TOKEN", "")
    anomaly_only = _env_bool("IDS_FORWARD_ANOMALY_ONLY", True)
    iface = os.environ.get("IDS_IFACE", "eth0")
    model_path = Path(os.environ.get("IDS_MODEL_PATH", "/models/br_rcs_l1m/autoencoder.joblib"))
    threshold_raw = os.environ.get("IDS_DECISION_THRESHOLD", "100")
    decision_threshold = float(threshold_raw) if threshold_raw not in {"", "none", "None"} else None

    print(
        (
            f"[ids-forwarder] iface={iface} model={model_path} threshold={decision_threshold} "
            f"forwarding={pipeline_url} anomaly_only={anomaly_only}"
        ),
        file=sys.stderr,
        flush=True,
    )

    try:
        flow_iter = iter_scored_interface_flows(
            interface=iface,
            model_path=model_path,
            decision_threshold=decision_threshold,
        )
    except Exception as exc:
        print(f"[ids-forwarder] failed to initialize IDS iterator: {exc}", file=sys.stderr, flush=True)
        return 1

    for record in flow_iter:
        webapp_record = normalize_to_webapp(record)

        # Keep original IDS output in container logs for debugging.
        print(json.dumps(webapp_record, sort_keys=True), flush=True)

        anomaly = bool(webapp_record.get("anomaly", False))
        if anomaly_only and not anomaly:
            continue

        event = _build_event(webapp_record)
        try:
            _post_json(pipeline_url, event, siem_token)
        except (error.URLError, TimeoutError, RuntimeError) as exc:
            print(f"[ids-forwarder] failed to forward event: {exc}", file=sys.stderr, flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
