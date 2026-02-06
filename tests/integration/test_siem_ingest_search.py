import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_siem_ingest_and_search(siem_client):
    payload = [
        {
            "event_type": "suricata.alert",
            "source": "suricata",
            "timestamp": "2026-02-06T10:00:00Z",
            "message": "alert one",
            "severity": 3,
            "asset_ip": "10.0.0.10",
        },
        {
            "event_type": "zeek.conn",
            "source": "zeek",
            "timestamp": "2026-02-06T10:05:00Z",
            "message": "conn",
            "severity": 1,
            "asset_ip": "10.0.0.11",
        },
    ]

    ingest_resp = siem_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    search_resp = siem_client.get(
        reverse("dashboard:siem_event_search"),
        {
            "event_type": "suricata.alert",
            "start": "2026-02-06T09:00:00Z",
            "end": "2026-02-06T11:00:00Z",
        },
    )
    assert search_resp.status_code == 200
    body = search_resp.json()
    assert body["count"] == 1
    assert body["results"][0]["event_type"] == "suricata.alert"
