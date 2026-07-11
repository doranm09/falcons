from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from .siem_pipeline import SiemPipelineError


def _first_value(payload: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    return None


def _sensor_interface_name(sensor: Dict[str, Any]) -> str | None:
    interface = sensor.get("interface")
    if interface:
        return str(interface)
    interfaces = sensor.get("interfaces")
    if isinstance(interfaces, list) and interfaces:
        return str(interfaces[0])
    return None


def _format_endpoint(ip: Any, port: Any) -> str:
    if ip in (None, ""):
        return ""
    if port in (None, ""):
        return str(ip)
    return f"{ip}:{port}"


def _suricata_event_type(payload: Dict[str, Any]) -> str:
    event_type = str(payload.get("event_type") or "event").strip().lower()
    return f"suricata.{event_type}" if event_type else "suricata.event"


def _suricata_summary(payload: Dict[str, Any]) -> str:
    event_type = str(payload.get("event_type") or "event").strip().lower()
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    dns = payload.get("dns") if isinstance(payload.get("dns"), dict) else {}
    http = payload.get("http") if isinstance(payload.get("http"), dict) else {}
    tls = payload.get("tls") if isinstance(payload.get("tls"), dict) else {}
    fileinfo = payload.get("fileinfo") if isinstance(payload.get("fileinfo"), dict) else {}
    endpoint = " -> ".join(
        part
        for part in (
            _format_endpoint(payload.get("src_ip"), payload.get("src_port")),
            _format_endpoint(payload.get("dest_ip"), payload.get("dest_port")),
        )
        if part
    )
    if alert.get("signature"):
        return str(alert["signature"])
    if event_type == "dns":
        query = dns.get("rrname") or dns.get("query")
        if query:
            return f"DNS query {query}"
    if event_type == "http":
        method = http.get("http_method") or http.get("method")
        host = http.get("hostname") or http.get("host")
        url = http.get("url")
        if method or host or url:
            target = f"{host or ''}{url or ''}".strip() or host or url or endpoint
            return f"HTTP {method or 'request'} {target}".strip()
    if event_type in {"tls", "ssl"}:
        peer = tls.get("sni") or tls.get("subject")
        if peer:
            return f"TLS {peer}"
    if event_type in {"fileinfo", "file"}:
        filename = fileinfo.get("filename") or fileinfo.get("magic")
        if filename:
            return f"File transfer {filename}"
    if payload.get("flow_id"):
        detail = f" {endpoint}" if endpoint else ""
        return f"Suricata flow {payload['flow_id']}{detail}"
    if endpoint:
        return f"Suricata {event_type} {endpoint}"
    return ""


def _suricata_severity(payload: Dict[str, Any]) -> Any:
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    return payload.get("severity", alert.get("severity"))


def transform_suricata_event(payload: Dict[str, Any], sensor: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise SiemPipelineError("Suricata event payload must be an object")

    sensor = sensor or {}
    event_type = _suricata_event_type(payload)
    asset_ip = payload.get("src_ip") or payload.get("dest_ip")
    asset_id = sensor.get("sensor_id") or sensor.get("hostname") or payload.get("host")
    message = _suricata_summary(payload)

    raw = dict(payload)
    raw.setdefault("event", {})
    if isinstance(raw["event"], dict):
        raw["event"].setdefault("module", "suricata")
        raw["event"].setdefault("dataset", event_type)
    if sensor:
        interface_name = _sensor_interface_name(sensor)
        raw.setdefault("observer", {}).update(
            {
                "name": sensor.get("hostname") or sensor.get("sensor_id"),
                "type": "sensor",
                "ingress": {"interface": {"name": interface_name}},
            }
        )
        if isinstance(sensor.get("interfaces"), list):
            raw["observer"]["interfaces"] = sensor.get("interfaces")

    return {
        "event_type": event_type,
        "event_module": "suricata",
        "event_dataset": event_type,
        "source": "suricata",
        "timestamp": payload.get("timestamp") or payload.get("@timestamp"),
        "message": message,
        "severity": _suricata_severity(payload),
        "asset_ip": asset_ip,
        "asset_id": asset_id,
        "source_ip": _first_value(payload, "src_ip"),
        "source_port": _first_value(payload, "src_port"),
        "destination_ip": _first_value(payload, "dest_ip"),
        "destination_port": _first_value(payload, "dest_port"),
        "raw": raw,
    }


def unpack_suricata_payload(body: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if isinstance(body, list):
        return {}, body
    if not isinstance(body, dict):
        raise SiemPipelineError("Suricata ingest body must be an object or list")

    sensor = body.get("sensor") if isinstance(body.get("sensor"), dict) else {}
    events = body.get("events")
    if events is None:
        events = [body]
    if not isinstance(events, list):
        raise SiemPipelineError("Suricata events must be a list")
    return sensor, events


def transform_suricata_events(body: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    sensor, events = unpack_suricata_payload(body)
    return sensor, [transform_suricata_event(event, sensor=sensor) for event in events]
