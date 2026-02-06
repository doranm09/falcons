from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .siem_query import parse_search_request, search_siem_events


def parse_hunt_tags(value: str) -> List[str]:
    if not value:
        return []
    tags = [tag.strip() for tag in value.split(",") if tag.strip()]
    deduped = []
    seen = set()
    for tag in tags:
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(tag)
    return deduped


def clean_query_params(params: Dict[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for key, value in params.items():
        if value in (None, ""):
            continue
        cleaned[key] = value
    return cleaned


def validate_hunt_query(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate search params using existing SIEM query parsing."""
    return parse_search_request(params)


def replay_hunt_search(params: Dict[str, Any]) -> Dict[str, Any]:
    parsed = parse_search_request(params)
    return search_siem_events(parsed)


def build_query_payload_from_form(data: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "event_type",
        "source",
        "asset_id",
        "asset_ip",
        "q",
        "severity",
        "start",
        "end",
        "limit",
        "offset",
        "event_type_in",
        "source_in",
        "agg",
        "agg_size",
    }
    payload: Dict[str, Any] = {}
    for key in allowed:
        if key in data:
            payload[key] = data.get(key)
    return clean_query_params(payload)
