import json

import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import AgentStatus


@pytest.mark.django_db
def test_siem_adapter_ingest_flow(siem_client):
    agent = AgentStatus.objects.create(
        agent_id="agent-99",
        hostname="host-z",
        ip_address="10.10.0.9",
        status="online",
        last_heartbeat=timezone.now(),
    )
    adapter_resp = siem_client.get(reverse("dashboard:siem_adapter_agent", args=[agent.agent_id]))
    assert adapter_resp.status_code == 200
    payload = adapter_resp.json()

    ingest_resp = siem_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    search_resp = siem_client.get(reverse("dashboard:siem_event_search"), {"event_type": "agent.heartbeat"})
    assert search_resp.status_code == 200
    body = search_resp.json()
    assert body["count"] == 1
