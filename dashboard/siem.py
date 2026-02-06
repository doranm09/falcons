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


def normalize_siem_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise SiemNormalizeError("Event payload must be an object")

    event_obj = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    host_obj = payload.get("host") if isinstance(payload.get("host"), dict) else {}

    timestamp = _parse_timestamp(
        payload.get("timestamp")
        or payload.get("@timestamp")
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
        or payload.get("src_ip")
        or payload.get("source_ip")
        or payload.get("ip")
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
        "severity": severity,
        "asset_id": str(asset_id)[:128] if asset_id else None,
        "asset_ip": asset_ip,
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
