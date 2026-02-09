import json

import pytest
from django.utils import timezone

from dashboard.models import SiemEvent
from dashboard.siem_export import EXPORT_SCHEMA_VERSION, ndjson_stream, serialize_event


@pytest.mark.django_db
def test_serialize_event_includes_schema():
    event = SiemEvent.objects.create(
        timestamp=timezone.now(),
        source="test",
        event_type="test.event",
        severity=1,
        asset_id="asset",
        asset_ip="10.0.0.1",
        summary="summary",
        raw={"k": "v"},
    )
    payload = serialize_event(event, EXPORT_SCHEMA_VERSION)
    assert payload["schema_version"] == EXPORT_SCHEMA_VERSION
    assert payload["event_type"] == "test.event"


@pytest.mark.django_db
def test_ndjson_stream_outputs_lines():
    event = SiemEvent.objects.create(
        timestamp=timezone.now(),
        source="test",
        event_type="test.event",
        severity=1,
        asset_id="asset",
        asset_ip="10.0.0.1",
        summary="summary",
        raw={"k": "v"},
    )
    lines = list(ndjson_stream([event], EXPORT_SCHEMA_VERSION))
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["schema_version"] == EXPORT_SCHEMA_VERSION
    assert data["event_type"] == "test.event"
