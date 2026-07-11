import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import SiemEvent


@pytest.mark.django_db
def test_siem_event_search_filters_on_canonical_network_fields(client):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="suricata",
        event_type="suricata.alert",
        event_module="suricata",
        event_dataset="suricata.alert",
        observer_name="suricata-l1",
        source_ip="10.1.1.14",
        source_port=43000,
        destination_ip="10.1.1.10",
        destination_port=502,
        network_community_id="1:suricata",
        summary="a",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="zeek",
        event_type="zeek.conn",
        event_module="zeek",
        event_dataset="zeek.conn",
        observer_name="zeek-l1",
        source_ip="10.1.1.14",
        source_port=43100,
        destination_ip="10.1.1.10",
        destination_port=4840,
        network_community_id="1:abc123",
        summary="b",
        raw={},
    )

    resp = client.get(
        reverse("dashboard:siem_event_search"),
        {
            "event_module": "zeek",
            "event_dataset": "zeek.conn",
            "observer_name": "zeek-l1",
            "source_ip": "10.1.1.14",
            "source_port": 43100,
            "destination_ip": "10.1.1.10",
            "destination_port": 4840,
            "network_community_id": "1:abc123",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["event_module"] == "zeek"
    assert body["results"][0]["event_dataset"] == "zeek.conn"
    assert body["results"][0]["observer_name"] == "zeek-l1"
    assert body["results"][0]["source_port"] == 43100
    assert body["results"][0]["destination_port"] == 4840


@pytest.mark.django_db
def test_siem_event_search_accepts_multi_value_network_filters(client):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="agent",
        event_type="agent.network_connection",
        event_module="agent",
        event_dataset="agent.network_connection",
        source_ip="10.2.50.20",
        source_port=44000,
        destination_ip="10.1.1.14",
        destination_port=44818,
        summary="engineering",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="agent",
        event_type="agent.network_connection",
        event_module="agent",
        event_dataset="agent.network_connection",
        source_ip="10.1.1.10",
        source_port=45000,
        destination_ip="10.1.1.9",
        destination_port=502,
        summary="field",
        raw={},
    )

    resp = client.get(
        reverse("dashboard:siem_event_search"),
        {
            "source_ip_in": "10.2.50.20,10.1.1.10",
            "destination_port_in": "44818",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["destination_port"] == 44818


@pytest.mark.django_db
def test_siem_event_search_excludes_stats_noise_by_flag(client):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="suricata",
        event_type="suricata.stats",
        event_module="suricata",
        event_dataset="suricata.stats",
        summary="stats",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="agent",
        event_type="agent.network_connection",
        event_module="agent",
        event_dataset="agent.network_connection",
        asset_ip="10.3.50.10",
        source_ip="10.3.50.10",
        destination_ip="10.4.50.20",
        summary="network",
        raw={},
    )

    resp = client.get(reverse("dashboard:siem_event_search"), {"exclude_stats": "1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["event_dataset"] == "agent.network_connection"
