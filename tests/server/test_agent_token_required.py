import json

import pytest
from django.test import override_settings
from django.urls import reverse


@pytest.mark.django_db
@override_settings(AGENT_API_TOKEN="agent-token", AGENT_API_TOKEN_REQUIRED=True)
def test_agent_report_requires_token(client):
    payload = {"agent_id": "token-agent", "hostname": "host"}
    resp = client.post(
        reverse("dashboard:agent_report"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 401

    ok_resp = client.post(
        reverse("dashboard:agent_report"),
        data=json.dumps(payload),
        content_type="application/json",
        HTTP_X_AGENT_TOKEN="agent-token",
    )
    assert ok_resp.status_code == 200
