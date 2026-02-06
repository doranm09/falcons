import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import SiemEvent


@pytest.mark.django_db
def test_siem_export_ndjson_endpoint(siem_analyst_client):
    SiemEvent.objects.create(
        timestamp=timezone.now(),
        source="test",
        event_type="test.event",
        severity=1,
        asset_id="asset",
        asset_ip="10.0.0.1",
        summary="summary",
        raw={"k": "v"},
    )
    resp = siem_analyst_client.get(reverse("dashboard:siem_export"), {"format": "ndjson"})
    assert resp.status_code == 200
    body = b"".join(resp.streaming_content)
    assert b"schema_version" in body
    assert b"test.event" in body
