import json

import pytest
from django.urls import reverse

from dashboard.models import SiemEvent


@pytest.mark.django_db
def test_siem_pipeline_ingest_endpoint(siem_client):
    payload = {
        "alert": {"signature": "ET MALWARE Example", "severity": 2},
        "src_ip": "10.1.1.12",
        "timestamp": "2026-02-06T12:05:00Z",
    }
    resp = siem_client.post(
        reverse("dashboard:siem_pipeline_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert SiemEvent.objects.count() == 1
