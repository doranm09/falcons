from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from django.conf import settings
from django.db import connections
from django.db.models import Count
from django.utils import timezone

from .models import SiemEvent


@dataclass
class SiemAggregationResult:
    field: str
    buckets: List[Dict[str, Any]]


def _parse_fields(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _parse_list(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _apply_filters(qs, params: Dict[str, Any]):
    if params.get("event_type"):
        qs = qs.filter(event_type=params["event_type"])
    if params.get("source"):
        qs = qs.filter(source=params["source"])
    if params.get("asset_id"):
        qs = qs.filter(asset_id=params["asset_id"])
    if params.get("asset_ip"):
        qs = qs.filter(asset_ip=params["asset_ip"])
    if params.get("severity") is not None:
        qs = qs.filter(severity=params["severity"])
    if params.get("query"):
        qs = qs.filter(summary__icontains=params["query"])
    if params.get("event_type_in"):
        qs = qs.filter(event_type__in=params["event_type_in"])
    if params.get("source_in"):
        qs = qs.filter(source__in=params["source_in"])
    return qs


def _build_aggregations(qs, fields: List[str], limit: int = 20) -> List[SiemAggregationResult]:
    results: List[SiemAggregationResult] = []
    for field in fields:
        buckets = list(
            qs.values(field)
            .annotate(count=Count("id"))
            .order_by("-count")[:limit]
        )
        results.append(SiemAggregationResult(field=field, buckets=buckets))
    return results


def search_siem_events(params: Dict[str, Any]) -> Dict[str, Any]:
    qs = SiemEvent.objects.all()

    start = params.get("start")
    end = params.get("end")
    if start:
        qs = qs.filter(timestamp__gte=start)
    if end:
        qs = qs.filter(timestamp__lte=end)

    qs = _apply_filters(qs, params)

    total = qs.count()
    offset = params.get("offset", 0)
    limit = params.get("limit", 100)

    items = []
    for event in qs[offset:offset + limit]:
        items.append(
            {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "asset_id": event.asset_id,
                "asset_ip": event.asset_ip,
                "summary": event.summary,
                "raw": event.raw,
            }
        )

    aggregations: List[SiemAggregationResult] = []
    if params.get("agg_fields"):
        aggregations = _build_aggregations(qs, params["agg_fields"], params.get("agg_size", 20))

    return {
        "count": total,
        "results": items,
        "aggregations": [
            {"field": agg.field, "buckets": agg.buckets} for agg in aggregations
        ],
    }


def parse_search_request(query_params) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "event_type": query_params.get("event_type"),
        "source": query_params.get("source"),
        "asset_id": query_params.get("asset_id"),
        "asset_ip": query_params.get("asset_ip"),
        "query": query_params.get("q"),
    }

    event_type_in = query_params.get("event_type_in")
    source_in = query_params.get("source_in")
    if event_type_in:
        params["event_type_in"] = _parse_list(event_type_in)
    if source_in:
        params["source_in"] = _parse_list(source_in)

    severity = query_params.get("severity")
    if severity not in (None, ""):
        params["severity"] = int(severity)
    else:
        params["severity"] = None

    from django.utils.dateparse import parse_datetime

    start = query_params.get("start")
    end = query_params.get("end")
    if start:
        start_dt = parse_datetime(start)
        if start_dt:
            if timezone.is_naive(start_dt):
                start_dt = timezone.make_aware(start_dt, timezone=timezone.utc)
            params["start"] = start_dt
    if end:
        end_dt = parse_datetime(end)
        if end_dt:
            if timezone.is_naive(end_dt):
                end_dt = timezone.make_aware(end_dt, timezone=timezone.utc)
            params["end"] = end_dt

    try:
        params["limit"] = max(1, min(int(query_params.get("limit", 100)), 500))
        params["offset"] = max(0, int(query_params.get("offset", 0)))
    except ValueError:
        params["limit"] = 100
        params["offset"] = 0

    agg_fields = query_params.get("agg") or ""
    if agg_fields:
        params["agg_fields"] = _parse_fields(agg_fields)
        try:
            params["agg_size"] = max(1, min(int(query_params.get("agg_size", 20)), 100))
        except ValueError:
            params["agg_size"] = 20

    return params
