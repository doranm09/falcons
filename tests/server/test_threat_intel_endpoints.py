import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_threat_intel_ingest_and_list(client):
    payload = {
        "indicators": [
            {"indicator_type": "ip", "value": "10.10.0.12"},
            {"indicator_type": "domain", "value": "bad.example"},
        ]
    }
    resp = client.post(
        reverse("dashboard:siem_threat_intel_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 200
    list_resp = client.get(reverse("dashboard:siem_threat_intel_list"))
    assert list_resp.status_code == 200
    body = list_resp.json()
    assert body["count"] >= 2
