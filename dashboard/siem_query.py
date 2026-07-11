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


def _parse_int_list(value: str, field: str) -> List[int]:
    values: List[int] = []
    for part in _parse_list(value):
        try:
            port = int(part)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid {field}")
        if port < 0 or port > 65535:
            raise ValueError(f"Invalid {field}")
        values.append(port)
    return values


def _apply_filters(qs, params: Dict[str, Any]):
    if params.get("event_type"):
        qs = qs.filter(event_type=params["event_type"])
    if params.get("source"):
        qs = qs.filter(source=params["source"])
    if params.get("event_module"):
        qs = qs.filter(event_module=params["event_module"])
    if params.get("event_dataset"):
        qs = qs.filter(event_dataset=params["event_dataset"])
    if params.get("observer_name"):
        qs = qs.filter(observer_name=params["observer_name"])
    if params.get("asset_id"):
        qs = qs.filter(asset_id=params["asset_id"])
    if params.get("asset_ip"):
        qs = qs.filter(asset_ip=params["asset_ip"])
    if params.get("source_ip"):
        qs = qs.filter(source_ip=params["source_ip"])
    if params.get("source_port") is not None:
        qs = qs.filter(source_port=params["source_port"])
    if params.get("destination_ip"):
        qs = qs.filter(destination_ip=params["destination_ip"])
    if params.get("destination_port") is not None:
        qs = qs.filter(destination_port=params["destination_port"])
    if params.get("network_community_id"):
        qs = qs.filter(network_community_id=params["network_community_id"])
    if params.get("severity") is not None:
        qs = qs.filter(severity=params["severity"])
    if params.get("query"):
        qs = qs.filter(summary__icontains=params["query"])
    if params.get("event_type_in"):
        qs = qs.filter(event_type__in=params["event_type_in"])
    if params.get("source_in"):
        qs = qs.filter(source__in=params["source_in"])
    if params.get("event_module_in"):
        qs = qs.filter(event_module__in=params["event_module_in"])
    if params.get("event_dataset_in"):
        qs = qs.filter(event_dataset__in=params["event_dataset_in"])
    if params.get("observer_name_in"):
        qs = qs.filter(observer_name__in=params["observer_name_in"])
    if params.get("asset_ip_in"):
        qs = qs.filter(asset_ip__in=params["asset_ip_in"])
    if params.get("source_ip_in"):
        qs = qs.filter(source_ip__in=params["source_ip_in"])
    if params.get("source_port_in"):
        qs = qs.filter(source_port__in=params["source_port_in"])
    if params.get("destination_ip_in"):
        qs = qs.filter(destination_ip__in=params["destination_ip_in"])
    if params.get("destination_port_in"):
        qs = qs.filter(destination_port__in=params["destination_port_in"])
    if params.get("exclude_stats"):
        qs = qs.exclude(event_dataset__endswith=".stats")
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
                "event_module": event.event_module,
                "event_dataset": event.event_dataset,
                "observer_name": event.observer_name,
                "severity": event.severity,
                "asset_id": event.asset_id,
                "asset_ip": event.asset_ip,
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "network_community_id": event.network_community_id,
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
        "event_module": query_params.get("event_module"),
        "event_dataset": query_params.get("event_dataset"),
        "observer_name": query_params.get("observer_name"),
        "asset_id": query_params.get("asset_id"),
        "asset_ip": query_params.get("asset_ip"),
        "source_ip": query_params.get("source_ip"),
        "source_port": query_params.get("source_port"),
        "destination_ip": query_params.get("destination_ip"),
        "destination_port": query_params.get("destination_port"),
        "network_community_id": query_params.get("network_community_id"),
        "query": query_params.get("q"),
        "exclude_stats": str(query_params.get("exclude_stats", "0")).strip().lower() in {"1", "true", "yes", "on"},
    }

    event_type_in = query_params.get("event_type_in")
    source_in = query_params.get("source_in")
    event_module_in = query_params.get("event_module_in")
    event_dataset_in = query_params.get("event_dataset_in")
    observer_name_in = query_params.get("observer_name_in")
    asset_ip_in = query_params.get("asset_ip_in")
    source_ip_in = query_params.get("source_ip_in")
    source_port_in = query_params.get("source_port_in")
    destination_ip_in = query_params.get("destination_ip_in")
    destination_port_in = query_params.get("destination_port_in")
    if event_type_in:
        params["event_type_in"] = _parse_list(event_type_in)
    if source_in:
        params["source_in"] = _parse_list(source_in)
    if event_module_in:
        params["event_module_in"] = _parse_list(event_module_in)
    if event_dataset_in:
        params["event_dataset_in"] = _parse_list(event_dataset_in)
    if observer_name_in:
        params["observer_name_in"] = _parse_list(observer_name_in)
    if asset_ip_in:
        params["asset_ip_in"] = _parse_list(asset_ip_in)
    if source_ip_in:
        params["source_ip_in"] = _parse_list(source_ip_in)
    if source_port_in:
        params["source_port_in"] = _parse_int_list(source_port_in, "source_port_in")
    if destination_ip_in:
        params["destination_ip_in"] = _parse_list(destination_ip_in)
    if destination_port_in:
        params["destination_port_in"] = _parse_int_list(destination_port_in, "destination_port_in")

    severity = query_params.get("severity")
    if severity not in (None, ""):
        try:
            params["severity"] = int(severity)
        except (TypeError, ValueError):
            raise ValueError("Invalid severity")
    else:
        params["severity"] = None

    for field in ("source_port", "destination_port"):
        value = params.get(field)
        if value in (None, ""):
            params[field] = None
            continue
        try:
            params[field] = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid {field}")
        if params[field] < 0 or params[field] > 65535:
            raise ValueError(f"Invalid {field}")

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
    except (TypeError, ValueError):
        raise ValueError("Invalid limit")
    try:
        params["offset"] = max(0, int(query_params.get("offset", 0)))
    except (TypeError, ValueError):
        raise ValueError("Invalid offset")

    agg_fields = query_params.get("agg") or ""
    if agg_fields:
        params["agg_fields"] = _parse_fields(agg_fields)
        try:
            params["agg_size"] = max(1, min(int(query_params.get("agg_size", 20)), 100))
        except (TypeError, ValueError):
            raise ValueError("Invalid agg_size")

    return params
