from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from django.conf import settings
from django.db import transaction

from .models import ThreatIntelIndicator, ThreatIntelMatch, SiemEvent


def _normalize_indicator_type(value: str) -> str:
    mapping = {
        "ip-src": "ip",
        "ip-dst": "ip",
        "ip": "ip",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "hash": "hash",
    }
    return mapping.get(value.lower().strip(), value.lower().strip())


def parse_ioc_payload(payload: Any) -> List[Dict[str, Any]]:
    indicators: List[Dict[str, Any]] = []

    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            indicators.append(item)
        return indicators

    if isinstance(payload, dict):
        if "indicators" in payload and isinstance(payload["indicators"], list):
            return [item for item in payload["indicators"] if isinstance(item, dict)]

        # MISP-like JSON
        if "Attribute" in payload and isinstance(payload["Attribute"], list):
            for attr in payload["Attribute"]:
                if not isinstance(attr, dict):
                    continue
                indicators.append(
                    {
                        "value": attr.get("value"),
                        "indicator_type": attr.get("type"),
                        "source": payload.get("Orgc", {}).get("name") or payload.get("Org", {}).get("name"),
                        "description": attr.get("comment") or "",
                        "confidence": None,
                        "tlp": payload.get("Event", {}).get("threat_level_id"),
                    }
                )
            return indicators

        if "Event" in payload and isinstance(payload["Event"], dict):
            event = payload["Event"]
            attrs = event.get("Attribute") or []
            if isinstance(attrs, list):
                for attr in attrs:
                    if not isinstance(attr, dict):
                        continue
                    indicators.append(
                        {
                            "value": attr.get("value"),
                            "indicator_type": attr.get("type"),
                            "source": event.get("Orgc", {}).get("name") or event.get("Org", {}).get("name"),
                            "description": attr.get("comment") or "",
                            "confidence": None,
                            "tlp": event.get("threat_level_id"),
                        }
                    )
            return indicators

    return indicators


def ingest_indicators(payload: Any) -> Dict[str, int]:
    items = parse_ioc_payload(payload)
    created = 0
    updated = 0

    for item in items:
        value = item.get("value") or item.get("indicator")
        indicator_type = item.get("indicator_type") or item.get("type")
        if not value or not indicator_type:
            continue
        indicator_type = _normalize_indicator_type(str(indicator_type))
        if indicator_type not in {"ip", "domain", "url", "hash"}:
            continue
        defaults = {
            "source": item.get("source") or "",
            "description": item.get("description") or "",
            "confidence": item.get("confidence"),
            "tlp": str(item.get("tlp")) if item.get("tlp") is not None else "",
            "active": True if item.get("active") is None else bool(item.get("active")),
        }
        indicator, was_created = ThreatIntelIndicator.objects.get_or_create(
            indicator_type=indicator_type,
            value=str(value),
            defaults=defaults,
        )
        if was_created:
            created += 1
        else:
            updated = updated + 1
            for field, val in defaults.items():
                setattr(indicator, field, val)
            indicator.save(update_fields=list(defaults.keys()))
    return {"created": created, "updated": updated}


def _event_text(event: Dict[str, Any]) -> str:
    parts = [
        str(event.get("summary") or ""),
        str(event.get("source") or ""),
        str(event.get("event_type") or ""),
        str(event.get("raw") or ""),
    ]
    return " ".join(parts).lower()


def match_indicators(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not getattr(settings, "THREAT_INTEL_ENABLED", True):
        return events

    indicators = list(ThreatIntelIndicator.objects.filter(active=True))
    if not indicators:
        return events

    for event in events:
        matches = []
        text = _event_text(event)
        asset_ip = str(event.get("asset_ip") or "")
        asset_id = str(event.get("asset_id") or "")
        for indicator in indicators:
            value = indicator.value.lower()
            if indicator.indicator_type == "ip":
                if asset_ip and value == asset_ip.lower():
                    matches.append((indicator, "asset_ip", indicator.value))
                elif value in text:
                    matches.append((indicator, "raw", indicator.value))
            elif indicator.indicator_type in {"domain", "url", "hash"}:
                if value in text:
                    matches.append((indicator, "raw", indicator.value))

        event["ioc_matches"] = [
            {"id": ind.id, "type": ind.indicator_type, "value": ind.value, "field": field}
            for ind, field, _ in matches
        ]
        event["ioc_match_count"] = len(matches)
    return events


def persist_ioc_matches(events: List[Dict[str, Any]], event_objects: List[SiemEvent]) -> int:
    if not getattr(settings, "THREAT_INTEL_ENABLED", True):
        return 0

    event_map = {obj.id: obj for obj in event_objects if obj.id}
    match_count = 0
    matches_to_create: List[ThreatIntelMatch] = []

    for event, obj in zip(events, event_objects):
        if not obj or not obj.id:
            continue
        for match in event.get("ioc_matches", []):
            try:
                indicator_id = match.get("id")
                indicator = ThreatIntelIndicator.objects.filter(id=indicator_id).first()
                if not indicator:
                    continue
                matches_to_create.append(
                    ThreatIntelMatch(
                        indicator=indicator,
                        event=obj,
                        matched_field=match.get("field") or "raw",
                        matched_value=match.get("value") or indicator.value,
                    )
                )
                match_count += 1
            except Exception:
                continue

    if matches_to_create:
        ThreatIntelMatch.objects.bulk_create(matches_to_create, ignore_conflicts=True)

    return match_count
