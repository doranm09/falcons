import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_pipeline_ingest_then_search(client):
    payload = {
        "uid": "C2",
        "id_orig_h": "10.1.1.13",
        "ts": 1760088060,
    }
    ingest_resp = client.post(
        reverse("dashboard:siem_pipeline_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    search_resp = client.get(reverse("dashboard:siem_event_search"), {"event_type": "zeek.conn"})
    assert search_resp.status_code == 200
    body = search_resp.json()
    assert body["count"] == 1
