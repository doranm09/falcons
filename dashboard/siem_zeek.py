from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .siem_pipeline import SiemPipelineError, _epoch_to_iso


def _zeek_event_type(payload: Dict[str, Any]) -> str:
    log_type = (
        payload.get("log_type")
        or payload.get("_path")
        or payload.get("path")
        or payload.get("event_type")
        or "event"
    )
    return f"zeek.{str(log_type).strip().lower()}"


def _zeek_summary(payload: Dict[str, Any], event_type: str) -> str:
    if payload.get("uid"):
        return f"{event_type} {payload['uid']}"
    if payload.get("query"):
        return f"DNS query {payload['query']}"
    if payload.get("host"):
        return f"HTTP host {payload['host']}"
    return event_type


def transform_zeek_event(payload: Dict[str, Any], sensor: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise SiemPipelineError("Zeek event payload must be an object")

    sensor = sensor or {}
    event_type = _zeek_event_type(payload)
    raw = dict(payload)
    raw.setdefault("event", {})
    if isinstance(raw["event"], dict):
        raw["event"].setdefault("module", "zeek")
        raw["event"].setdefault("dataset", event_type)
    if sensor:
        raw.setdefault("observer", {}).update(
            {
                "name": sensor.get("hostname") or sensor.get("sensor_id"),
                "type": "sensor",
                "ingress": {"interface": {"name": sensor.get("interface")}},
            }
        )

    timestamp = payload.get("timestamp") or payload.get("@timestamp")
    if timestamp is None and payload.get("ts") is not None:
        timestamp = _epoch_to_iso(payload.get("ts"))

    return {
        "event_type": event_type,
        "source": "zeek",
        "timestamp": timestamp,
        "message": _zeek_summary(payload, event_type),
        "severity": payload.get("severity"),
        "asset_ip": (
            payload.get("id_orig_h")
            or payload.get("id.orig_h")
            or payload.get("src_ip")
            or payload.get("id_resp_h")
            or payload.get("id.resp_h")
        ),
        "asset_id": sensor.get("sensor_id") or sensor.get("hostname") or payload.get("uid"),
        "raw": raw,
    }


def unpack_zeek_payload(body: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if isinstance(body, list):
        return {}, body
    if not isinstance(body, dict):
        raise SiemPipelineError("Zeek ingest body must be an object or list")

    sensor = body.get("sensor") if isinstance(body.get("sensor"), dict) else {}
    logs = body.get("logs")
    if logs is None:
        logs = [body]
    if not isinstance(logs, list):
        raise SiemPipelineError("Zeek logs must be a list")
    return sensor, logs


def transform_zeek_events(body: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    sensor, logs = unpack_zeek_payload(body)
    return sensor, [transform_zeek_event(log, sensor=sensor) for log in logs]
