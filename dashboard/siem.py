from __future__ import annotations

from datetime import datetime
import ipaddress
from typing import Any, Dict, Optional

from django.utils import timezone
from django.utils.dateparse import parse_datetime


class SiemNormalizeError(ValueError):
    pass


class SiemQueryError(ValueError):
    pass


def _parse_timestamp(value: Any) -> datetime:
    if value in (None, ""):
        return timezone.now()
    if isinstance(value, datetime):
        ts = value
    else:
        ts = parse_datetime(str(value))
        if ts is None:
            raise SiemNormalizeError("Invalid timestamp")
    if timezone.is_naive(ts):
        ts = timezone.make_aware(ts, timezone=timezone.utc)
    return ts


def _coerce_int(value: Any, field: str) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SiemNormalizeError(f"Invalid {field}")


def _pick_first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _coerce_ip(value: Any) -> Optional[str]:
    value = _pick_first(value)
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise SiemNormalizeError("Invalid asset_ip")


def _coerce_optional_ip(value: Any, field: str) -> Optional[str]:
    value = _pick_first(value)
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise SiemNormalizeError(f"Invalid {field}")


def _coerce_optional_port(value: Any, field: str) -> Optional[int]:
    value = _pick_first(value)
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise SiemNormalizeError(f"Invalid {field}")
    if port < 0 or port > 65535:
        raise SiemNormalizeError(f"Invalid {field}")
    return port


def _coerce_str(value: Any, max_length: int) -> str:
    if value in (None, ""):
        return ""
    return str(value)[:max_length]


def normalize_siem_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise SiemNormalizeError("Event payload must be an object")

    raw_obj = payload.get("raw") if isinstance(payload.get("raw"), dict) else payload
    event_obj = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    if not event_obj and isinstance(raw_obj.get("event"), dict):
        event_obj = raw_obj["event"]
    host_obj = payload.get("host") if isinstance(payload.get("host"), dict) else {}
    if not host_obj and isinstance(raw_obj.get("host"), dict):
        host_obj = raw_obj["host"]
    observer_obj = raw_obj.get("observer") if isinstance(raw_obj.get("observer"), dict) else {}
    source_obj = raw_obj.get("source") if isinstance(raw_obj.get("source"), dict) else {}
    destination_obj = raw_obj.get("destination") if isinstance(raw_obj.get("destination"), dict) else {}
    network_obj = raw_obj.get("network") if isinstance(raw_obj.get("network"), dict) else {}

    timestamp = _parse_timestamp(
        payload.get("timestamp")
        or payload.get("@timestamp")
        or raw_obj.get("@timestamp")
        or event_obj.get("created")
        or event_obj.get("start")
    )

    event_type = (
        payload.get("event_type")
        or event_obj.get("type")
        or event_obj.get("category")
        or payload.get("type")
    )
    if not event_type:
        raise SiemNormalizeError("event_type is required")

    source = (
        payload.get("source")
        or payload.get("event_source")
        or payload.get("sensor")
        or payload.get("agent")
        or payload.get("agent_id")
        or "custom"
    )

    severity = _coerce_int(
        payload.get("severity")
        or event_obj.get("severity")
        or event_obj.get("risk_score"),
        "severity",
    )

    asset_id = (
        payload.get("asset_id")
        or host_obj.get("id")
        or payload.get("agent_id")
        or payload.get("host_id")
    )

    asset_ip = _coerce_ip(
        payload.get("asset_ip")
        or host_obj.get("ip")
        or raw_obj.get("asset_ip")
        or payload.get("src_ip")
        or payload.get("source_ip")
        or raw_obj.get("src_ip")
        or raw_obj.get("source_ip")
        or raw_obj.get("id_orig_h")
        or raw_obj.get("id.orig_h")
        or payload.get("ip")
    )

    event_module = _coerce_str(
        payload.get("event_module")
        or event_obj.get("module")
        or raw_obj.get("event_module"),
        100,
    )
    event_dataset = _coerce_str(
        payload.get("event_dataset")
        or event_obj.get("dataset")
        or raw_obj.get("event_dataset"),
        150,
    )
    observer_name = _coerce_str(
        payload.get("observer_name")
        or observer_obj.get("name")
        or raw_obj.get("observer_name"),
        255,
    )
    source_ip = _coerce_optional_ip(
        payload.get("source_ip")
        or payload.get("src_ip")
        or source_obj.get("ip")
        or raw_obj.get("src_ip")
        or raw_obj.get("source_ip")
        or raw_obj.get("id_orig_h")
        or raw_obj.get("id.orig_h"),
        "source_ip",
    )
    source_port = _coerce_optional_port(
        payload.get("source_port")
        or payload.get("src_port")
        or source_obj.get("port")
        or raw_obj.get("src_port")
        or raw_obj.get("source_port")
        or raw_obj.get("id_orig_p")
        or raw_obj.get("id.orig_p"),
        "source_port",
    )
    destination_ip = _coerce_optional_ip(
        payload.get("destination_ip")
        or payload.get("dest_ip")
        or destination_obj.get("ip")
        or raw_obj.get("dest_ip")
        or raw_obj.get("destination_ip")
        or raw_obj.get("id_resp_h")
        or raw_obj.get("id.resp_h"),
        "destination_ip",
    )
    destination_port = _coerce_optional_port(
        payload.get("destination_port")
        or payload.get("dest_port")
        or destination_obj.get("port")
        or raw_obj.get("dest_port")
        or raw_obj.get("destination_port")
        or raw_obj.get("id_resp_p")
        or raw_obj.get("id.resp_p"),
        "destination_port",
    )
    network_community_id = _coerce_str(
        payload.get("network_community_id")
        or network_obj.get("community_id")
        or raw_obj.get("network_community_id"),
        128,
    )

    summary = (
        payload.get("message")
        or payload.get("summary")
        or event_obj.get("action")
        or ""
    )

    return {
        "timestamp": timestamp,
        "source": str(source)[:100],
        "event_type": str(event_type)[:120],
        "event_module": event_module,
        "event_dataset": event_dataset,
        "observer_name": observer_name,
        "severity": severity,
        "asset_id": str(asset_id)[:128] if asset_id else None,
        "asset_ip": asset_ip,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "network_community_id": network_community_id,
        "summary": str(summary)[:512],
        "raw": payload,
    }


def parse_siem_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize SIEM search parameters."""
    event_type = params.get("event_type") or None
    source = params.get("source") or None
    asset_id = params.get("asset_id") or None
    asset_ip = params.get("asset_ip") or None
    query = params.get("q") or None
    severity = params.get("severity")

    if severity in ("", None):
        severity_value = None
    else:
        try:
            severity_value = _coerce_int(severity, "severity")
        except SiemNormalizeError:
            raise SiemQueryError("Invalid severity")

    try:
        limit = int(params.get("limit", "100"))
    except (TypeError, ValueError):
        raise SiemQueryError("Invalid limit")
    try:
        offset = int(params.get("offset", "0"))
    except (TypeError, ValueError):
        raise SiemQueryError("Invalid offset")

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    return {
        "event_type": event_type,
        "source": source,
        "asset_id": asset_id,
        "asset_ip": asset_ip,
        "query": query,
        "severity": severity_value,
        "limit": limit,
        "offset": offset,
    }
