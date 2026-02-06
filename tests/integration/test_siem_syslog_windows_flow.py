import json

import pytest
from django.urls import reverse

from dashboard.models import SiemEvent


@pytest.mark.django_db
def test_syslog_windows_ingest_flow(client):
    syslog_data = "<34>Oct 11 22:14:15 host1 sshd[123]: test\n"
    syslog_resp = client.post(
        reverse("dashboard:siem_syslog_ingest"),
        data=syslog_data,
        content_type="text/plain",
    )
    assert syslog_resp.status_code == 201

    windows_payload = {
        "system": {"event_id": 4625, "computer": "WIN-HOST"},
        "provider": {"name": "Microsoft-Windows-Security-Auditing"},
        "timestamp": "2026-02-06T12:55:00Z",
        "message": "An account failed to log on",
    }
    windows_resp = client.post(
        reverse("dashboard:siem_windows_ingest"),
        data=json.dumps(windows_payload),
        content_type="application/json",
    )
    assert windows_resp.status_code == 201

    assert SiemEvent.objects.filter(event_type="syslog.message").count() == 1
    assert SiemEvent.objects.filter(event_type="windows.event").count() == 1
