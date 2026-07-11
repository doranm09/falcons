import json
from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from dashboard.models import AgentStatus, NetworkConnection, Node, NodeInterface, SiemEvent, SiemSensorStatus


@pytest.mark.django_db
@override_settings(AGENT_API_TOKEN="test-token", AGENT_API_TOKEN_REQUIRED=True)
def test_agent_network_metadata_route_updates_inventory_and_ports(client):
    agent = AgentStatus.objects.create(
        agent_id="agent-metadata-1",
        hostname="plc-main",
        ip_address="172.31.250.14",
    )
    payload = {
        "agent_id": agent.agent_id,
        "network_connections": [
            {
                "protocol": "TCP",
                "local_address": "10.1.1.14:8080",
                "remote_address": "10.3.50.10:443",
                "status": "ESTABLISHED",
                "process": {"name": "curl", "pid": 4321, "username": "demo"},
            }
        ],
        "interface_statistics": [],
        "active_ports": [{"port": 44818, "protocol": "tcp", "state": "LISTEN"}],
        "interfaces": [
            {"name": "eth0", "ip": "10.1.1.14", "mac": "00:aa:bb:cc:dd:01"},
            {"name": "eth1", "ip": "10.1.2.14", "mac": "00:aa:bb:cc:dd:02"},
        ],
    }

    response = client.post(
        reverse("dashboard:agent_network_metadata"),
        data=json.dumps(payload),
        content_type="application/json",
        HTTP_X_AGENT_TOKEN="test-token",
    )

    assert response.status_code == 200
    connection = NetworkConnection.objects.get(agent=agent)
    assert connection.local_address == "10.1.1.14"
    assert connection.local_port == 8080
    assert connection.remote_address == "10.3.50.10"
    assert connection.remote_port == 443

    agent.refresh_from_db()
    assert agent.ip_address == "10.1.1.14"
    assert agent.interfaces == payload["interfaces"]
    assert agent.active_ports == payload["active_ports"]

    node = Node.objects.get(agent_id=agent.agent_id)
    assert node.ip_address == "10.1.1.14"
    assert node.active_ports == payload["active_ports"]
    assert NodeInterface.objects.filter(node=node).count() == 2


@pytest.mark.django_db
@override_settings(
    SIEM_INGEST_TOKEN="sensor-token",
    SIEM_SENSOR_TOKEN="sensor-token",
    SIEM_INGEST_TOKEN_REQUIRED=True,
)
def test_siem_suricata_sensor_ingest_creates_events_and_sensor_status(client):
    payload = {
        "sensor": {
            "sensor_id": "suricata-sensor",
            "hostname": "suricata-sensor",
            "interface": "mirror0",
        },
        "events": [
            {
                "timestamp": timezone.now().isoformat(),
                "event_type": "alert",
                "src_ip": "10.1.1.14",
                "src_port": 502,
                "dest_ip": "10.3.50.10",
                "dest_port": 443,
                "alert": {"signature": "Test Suricata Alert", "severity": 7},
            }
        ],
    }

    response = client.post(
        reverse("dashboard:siem_suricata_sensor_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
        HTTP_X_SIEM_TOKEN="sensor-token",
    )

    assert response.status_code == 201
    sensor = SiemSensorStatus.objects.get(sensor_id="suricata-sensor")
    assert sensor.status == "online"
    assert sensor.event_count == 1
    assert sensor.interface_names == ["mirror0"]

    event = SiemEvent.objects.get(source="suricata")
    assert event.event_module == "suricata"
    assert event.event_dataset == "suricata.alert"
    assert event.observer_name == "suricata-sensor"
    assert event.source_ip == "10.1.1.14"
    assert event.destination_ip == "10.3.50.10"


@pytest.mark.django_db
@override_settings(SIEM_SENSOR_HEALTH_LOOKBACK_SEC=60)
def test_siem_sensor_health_api_marks_stale_sensors(client):
    SiemSensorStatus.objects.create(
        sensor_id="zeek-sensor",
        sensor_type="zeek",
        hostname="zeek-sensor",
        status="online",
        last_seen=timezone.now() - timedelta(minutes=10),
        event_count=5,
        interface_names=["mirror1"],
    )

    response = client.get(reverse("dashboard:siem_sensor_health_api"))

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["stale"] == 1
    assert payload["sensors"][0]["sensor_id"] == "zeek-sensor"
    assert payload["sensors"][0]["status"] == "stale"
