import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_syslog_ingest_endpoint(client):
    data = "<34>Oct 11 22:14:15 host1 sshd[123]: test\n"
    resp = client.post(reverse("dashboard:siem_syslog_ingest"), data=data, content_type="text/plain")
    assert resp.status_code == 201


@pytest.mark.django_db
def test_windows_ingest_endpoint(client):
    payload = {
        "system": {"event_id": 4625, "computer": "WIN-HOST"},
        "provider": {"name": "Microsoft-Windows-Security-Auditing"},
        "timestamp": "2026-02-06T12:55:00Z",
        "message": "An account failed to log on",
    }
    resp = client.post(
        reverse("dashboard:siem_windows_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
