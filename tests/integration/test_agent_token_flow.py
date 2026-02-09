import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_agent_report_with_token_updates_status(agent_client):
    payload = {
        "agent_id": "secure-agent",
        "hostname": "secure-host",
        "interfaces": [{"name": "eth0", "ip": "10.0.0.50", "mac": "00:11:22:33:44:55"}],
    }
    resp = agent_client.post(
        reverse("dashboard:agent_report"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 200

    status_resp = agent_client.get(reverse("dashboard:agent_status_api"))
    assert status_resp.status_code == 200
    body = status_resp.json()
    agent_ids = {item["agent_id"] for item in body.get("agents", [])}
    assert "secure-agent" in agent_ids
