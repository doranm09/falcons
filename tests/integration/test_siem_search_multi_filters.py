import json

import pytest
from django.urls import reverse

from dashboard.models import SiemEvent
from django.utils import timezone


@pytest.mark.django_db
def test_siem_search_multi_filters(client):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="suricata",
        event_type="suricata.alert",
        summary="a",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="zeek",
        event_type="zeek.conn",
        summary="b",
        raw={},
    )

    resp = client.get(
        reverse("dashboard:siem_event_search"),
        {"event_type_in": "zeek.conn", "source_in": "zeek"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["source"] == "zeek"
