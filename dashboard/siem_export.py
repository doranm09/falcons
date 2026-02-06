from __future__ import annotations

import json
from datetime import datetime
from typing import Iterable, Iterator, Optional

from django.utils import timezone

from .models import SiemEvent

EXPORT_SCHEMA_VERSION = "1.0"


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    from django.utils.dateparse import parse_datetime

    parsed = parse_datetime(value)
    if not parsed:
        return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone=timezone.utc)
    return parsed


def build_event_queryset(start: Optional[str], end: Optional[str]):
    qs = SiemEvent.objects.all()
    start_dt = _parse_datetime(start)
    end_dt = _parse_datetime(end)
    if start_dt:
        qs = qs.filter(timestamp__gte=start_dt)
    if end_dt:
        qs = qs.filter(timestamp__lte=end_dt)
    return qs


def serialize_event(event: SiemEvent, schema_version: str) -> dict:
    return {
        "schema_version": schema_version,
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


def ndjson_stream(events: Iterable[SiemEvent], schema_version: str) -> Iterator[str]:
    for event in events:
        payload = serialize_event(event, schema_version)
        yield json.dumps(payload) + "\n"


def export_parquet_bytes(events: Iterable[SiemEvent], schema_version: str) -> bytes:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pyarrow is required for Parquet export") from exc

    rows = [serialize_event(event, schema_version) for event in events]
    table = pa.Table.from_pylist(rows)
    sink = pa.BufferOutputStream()
    pq.write_table(table, sink)
    return sink.getvalue().to_pybytes()
