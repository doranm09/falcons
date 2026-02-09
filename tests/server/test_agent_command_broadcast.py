import json
import pytest

from django.urls import reverse

from dashboard.models import AgentStatus, AgentCommand


pytestmark = pytest.mark.django_db


def test_send_agent_command_broadcast(client):
    AgentStatus.objects.create(agent_id="a1", hostname="h1", ip_address="10.0.0.1")
    AgentStatus.objects.create(agent_id="a2", hostname="h2", ip_address="10.0.0.2")

    payload = {
        "agent_id": "all",
        "action": "ping",
        "parameters": {"target": "1.1.1.1"},
    }

    response = client.post(
        reverse("dashboard:send_agent_command"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "command_sent"
    assert data["count"] == 2
    assert AgentCommand.objects.count() == 2
