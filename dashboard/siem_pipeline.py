from __future__ import annotations

from datetime import datetime, timezone as dt_timezone
from typing import Any, Dict, Iterable, List, Tuple

from .siem import SiemNormalizeError


class SiemPipelineError(ValueError):
    pass


def _epoch_to_iso(value: Any) -> str:
    try:
        ts = float(value)
    except (TypeError, ValueError):
        raise SiemPipelineError("Invalid epoch timestamp")
    return datetime.fromtimestamp(ts, tz=dt_timezone.utc).isoformat()


def _infer_source(payload: Dict[str, Any]) -> str:
    if payload.get("source"):
        return str(payload["source"])
    if "alert" in payload and isinstance(payload.get("alert"), dict):
        return "suricata"
    if "id_orig_h" in payload or "uid" in payload:
        return "zeek"
    if payload.get("agent_id") or payload.get("hostname"):
        return "agent"
    if payload.get("scan_type") or payload.get("cidr"):
        return "scan"
    return "custom"


def _infer_event_type(payload: Dict[str, Any], source: str) -> str:
    if payload.get("event_type"):
        return str(payload["event_type"])
    if source == "suricata":
        return "suricata.alert" if "alert" in payload else "suricata.event"
    if source == "zeek":
        if "id_orig_h" in payload or "conn_state" in payload:
            return "zeek.conn"
        return "zeek.event"
    if source == "agent":
        return "agent.telemetry"
    if source == "scan":
        return "scan.run"
    return "custom.event"


def _infer_summary(payload: Dict[str, Any], source: str) -> str:
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    if payload.get("message"):
        return str(payload["message"])
    if raw.get("message"):
        return str(raw["message"])
    if source == "suricata":
        alert = payload.get("alert") or raw.get("alert") or {}
        signature = alert.get("signature")
        if signature:
            return str(signature)
    if source == "zeek":
        uid = payload.get("uid") or raw.get("uid")
        if uid:
            return f"Zeek event {uid}"
    if source == "scan":
        cidr = payload.get("cidr") or raw.get("cidr")
        scan_type = payload.get("scan_type") or raw.get("scan_type")
        if cidr and scan_type:
            return f"{scan_type} scan on {cidr}"
    if source == "ids":
        src_ip = payload.get("src_ip") or raw.get("src_ip")
        dst_ip = payload.get("dst_ip") or raw.get("dst_ip")
        src_port = payload.get("src_port") or raw.get("src_port")
        dst_port = payload.get("dst_port") or raw.get("dst_port")
        protocol = payload.get("protocol") or raw.get("protocol")
        if src_ip or dst_ip:
            flow = f"{src_ip or '-'}:{src_port or '-'} -> {dst_ip or '-'}:{dst_port or '-'}"
            if protocol:
                return f"IDS {protocol} flow {flow}"
            return f"IDS flow {flow}"
    return ""


def _infer_severity(payload: Dict[str, Any], source: str) -> Any:
    if payload.get("severity") is not None:
        return payload.get("severity")
    if source == "suricata":
        alert = payload.get("alert") or {}
        return alert.get("severity")
    return None


def _infer_asset(payload: Dict[str, Any]) -> Tuple[Any, Any]:
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    asset_ip = (
        payload.get("asset_ip")
        or raw.get("asset_ip")
        or payload.get("src_ip")
        or raw.get("src_ip")
        or payload.get("source_ip")
        or raw.get("source_ip")
        or payload.get("id_orig_h")
        or raw.get("id_orig_h")
        or payload.get("host_ip")
        or raw.get("host_ip")
    )
    asset_id = (
        payload.get("asset_id")
        or raw.get("asset_id")
        or payload.get("agent_id")
        or raw.get("agent_id")
        or payload.get("hostname")
        or raw.get("hostname")
    )
    return asset_ip, asset_id


def transform_pipeline_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise SiemPipelineError("Event payload must be an object")

    source = _infer_source(payload)
    event_type = _infer_event_type(payload, source)
    summary = _infer_summary(payload, source)
    severity = _infer_severity(payload, source)
    asset_ip, asset_id = _infer_asset(payload)

    timestamp = payload.get("timestamp") or payload.get("@timestamp")
    if timestamp is None and payload.get("ts") is not None:
        timestamp = _epoch_to_iso(payload.get("ts"))

    # Keep producer-provided raw content (if present) to avoid repeatedly
    # nesting wrappers at each pipeline stage.
    raw_payload = payload.get("raw") if isinstance(payload.get("raw"), dict) else payload

    event = {
        "event_type": event_type,
        "source": source,
        "timestamp": timestamp,
        "message": summary,
        "severity": severity,
        "asset_ip": asset_ip,
        "asset_id": asset_id,
        "raw": raw_payload,
    }
    return event


def transform_pipeline_events(payloads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for payload in payloads:
        events.append(transform_pipeline_event(payload))
    return events
