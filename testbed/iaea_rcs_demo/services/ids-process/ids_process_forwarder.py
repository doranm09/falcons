#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib import error
from urllib import request

from influxdb_client import InfluxDBClient

from ids_process import (
    _default_threshold_from_env,
    _load_live_inference_context,
    _parse_tag_keys,
    _query_rows,
    _score_row,
)


DEFAULT_PIPELINE_URL = "http://host.docker.internal:8000/dashboard/siem/pipeline/ingest/"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _post_json(url: str, payload: Dict[str, Any], token: str) -> None:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-SIEM-Token"] = token

    req = request.Request(url=url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=3) as response:
        if response.status >= 400:
            raise RuntimeError(f"SIEM ingest failed with status {response.status}")


def _build_event(sample_record: Dict[str, Any]) -> Dict[str, Any]:
    is_anomaly = bool(sample_record.get("anomaly", False))
    return {
        "source": "ids-process",
        "event_type": "ids.process.anomaly" if is_anomaly else "ids.process.sample",
        "timestamp": _iso_now(),
        "score": sample_record.get("score"),
        "decision_threshold": sample_record.get("decision_threshold"),
        "raw": sample_record,
    }


def iter_scored_process_samples(
    influx_url: str,
    influx_token: str,
    influx_org: str,
    influx_bucket: str,
    profile: str,
    measurement: str,
    tag_keys: list[str],
    watch_range_start: str,
    poll_interval: float,
    model_path: Path,
    decision_threshold: float | None,
):
    """Yield scored process sample dictionaries from historian polling."""
    context = _load_live_inference_context(model_path, decision_threshold)
    feature_keys: list[str] = context["feature_keys"]

    last_seen_timestamp = ""
    with InfluxDBClient(url=influx_url, token=influx_token, org=influx_org) as client:
        query_api = client.query_api()

        while True:
            try:
                rows = _query_rows(
                    query_api,
                    influx_bucket,
                    influx_org,
                    measurement,
                    profile,
                    feature_keys,
                    range_expr=watch_range_start,
                    limit=None,
                    desc=False,
                )

                new_rows = [
                    row
                    for row in rows
                    if (sample_ts := str(row.get("_time") or "")) and sample_ts > last_seen_timestamp
                ]
                if new_rows:
                    for row in new_rows:
                        sample_ts = str(row.get("_time") or "")
                        scored = _score_row(row, context)
                        sample_record = {
                            "profile": profile,
                            "measurement": measurement,
                            "timestamp": sample_ts,
                            "anomaly": scored["anomaly"],
                            "score": scored["score"],
                            "decision_threshold": scored["decision_threshold"],
                            "raw_time": sample_ts,
                            "fields": {k: row.get(k) for k in tag_keys},
                        }
                        yield sample_record

                    last_seen_timestamp = str(new_rows[-1].get("_time") or last_seen_timestamp)
            except Exception as exc:
                print(f"[ids-process-forwarder] polling loop error: {exc}", file=sys.stderr, flush=True)

            time.sleep(poll_interval)


def main() -> int:
    pipeline_url = os.environ.get("SIEM_PIPELINE_URL", DEFAULT_PIPELINE_URL)
    siem_token = os.environ.get("SIEM_INGEST_TOKEN", "")
    anomaly_only = _env_bool(
        "IDS_PROCESS_WATCH_ANOMALY_ONLY",
        _env_bool("IDS_PROCESS_FORWARD_ANOMALY_ONLY", True),
    )

    influx_url = os.environ.get("INFLUX_URL", "http://historian-db:8086")
    influx_token = os.environ.get("INFLUX_TOKEN", "iaea-historian-token")
    influx_org = os.environ.get("INFLUX_ORG", "iaea")
    influx_bucket = os.environ.get("INFLUX_BUCKET", "iaea_rcs")
    profile = os.environ.get("IDS_PROCESS_PROFILE", "main")
    measurement = os.environ.get("IDS_PROCESS_MEASUREMENT", "rcs_metrics")
    tag_keys = _parse_tag_keys(os.environ.get("IDS_PROCESS_TAG_KEYS", ""))
    watch_range_start = os.environ.get("IDS_PROCESS_WATCH_RANGE_START", "-5s")
    poll_interval = float(os.environ.get("IDS_PROCESS_POLL_INTERVAL", "1"))

    model_path = Path(os.environ.get("IDS_PROCESS_MODEL_PATH", "/models/ids-process/autoencoder.joblib"))
    decision_threshold = _default_threshold_from_env()

    print(
        (
            f"[ids-process-forwarder] profile={profile} measurement={measurement} "
            f"tags={len(tag_keys)} poll={poll_interval}s model={model_path} "
            f"watch_range={watch_range_start} threshold={decision_threshold} "
            f"forwarding={pipeline_url} anomaly_only={anomaly_only}"
        ),
        file=sys.stderr,
        flush=True,
    )

    try:
        sample_iter = iter_scored_process_samples(
            influx_url=influx_url,
            influx_token=influx_token,
            influx_org=influx_org,
            influx_bucket=influx_bucket,
            profile=profile,
            measurement=measurement,
            tag_keys=tag_keys,
            watch_range_start=watch_range_start,
            poll_interval=poll_interval,
            model_path=model_path,
            decision_threshold=decision_threshold,
        )
    except Exception as exc:
        print(f"[ids-process-forwarder] failed to initialize forwarder: {exc}", file=sys.stderr, flush=True)
        return 1

    for record in sample_iter:
        print(json.dumps(record, sort_keys=True), flush=True)

        anomaly = bool(record.get("anomaly", False))
        if anomaly_only and not anomaly:
            continue

        event: Dict[str, Any] = _build_event(record)
        try:
            _post_json(pipeline_url, event, siem_token)
        except (error.URLError, TimeoutError, RuntimeError) as exc:
            print(f"[ids-process-forwarder] failed to forward event: {exc}", file=sys.stderr, flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
