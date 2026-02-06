import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_siem_event_explorer_shows_ingested_event(client):
    payload = {
        "event_type": "agent.heartbeat",
        "source": "agent",
        "timestamp": "2026-02-06T11:00:00Z",
        "message": "Agent heartbeat",
        "severity": 1,
        "asset_ip": "10.10.0.5",
    }
    ingest_resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    page_resp = client.get(reverse("dashboard:siem_event_explorer"))
    assert page_resp.status_code == 200
    content = page_resp.content.decode("utf-8")
    assert "agent.heartbeat" in content
