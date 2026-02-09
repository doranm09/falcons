import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_export_after_ingest(siem_analyst_client):
    payload = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "timestamp": "2026-02-06T15:00:00Z",
        "message": "alert",
    }
    ingest_resp = siem_analyst_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    export_resp = siem_analyst_client.get(
        reverse("dashboard:siem_export"),
        {
            "format": "ndjson",
            "start": "2026-02-06T14:00:00Z",
            "end": "2026-02-06T16:00:00Z",
        },
    )
    assert export_resp.status_code == 200
    lines = b"".join(export_resp.streaming_content).decode("utf-8").strip().split("\n")
    assert len(lines) == 1
    assert "suricata.alert" in lines[0]
