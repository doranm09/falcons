import json

import pytest
from django.urls import reverse

from dashboard.models import Hunt, HuntSearch


@pytest.mark.django_db
def test_hunt_replay_returns_ingested_events(siem_analyst_client):
    hunt = Hunt.objects.create(name="Hunt Gamma", description="Integration")
    siem_analyst_client.post(
        reverse("dashboard:siem_hunt_add_search", args=[hunt.id]),
        data={"search_name": "Zeek", "event_type": "zeek.conn"},
    )
    search = HuntSearch.objects.get(hunt=hunt)

    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:30:00Z",
        "message": "conn observed",
    }
    ingest_resp = siem_analyst_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    replay_resp = siem_analyst_client.get(
        reverse("dashboard:siem_hunt_replay_search", args=[hunt.id, search.id])
    )
    assert replay_resp.status_code == 200
    body = replay_resp.json()
    assert body["count"] == 1
    assert body["results"][0]["event_type"] == "zeek.conn"
