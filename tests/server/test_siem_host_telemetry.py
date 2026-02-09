import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_pipeline_ingest_osquery_event(siem_client):
    payload = {
        "event_type": "osquery.result",
        "source": "osquery",
        "timestamp": "2026-02-06T12:50:00Z",
        "message": "osquery: select 1",
        "raw": {"query": "select 1", "results": [{"x": 1}]},
    }
    resp = siem_client.post(
        reverse("dashboard:siem_pipeline_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["ingested"] == 1
