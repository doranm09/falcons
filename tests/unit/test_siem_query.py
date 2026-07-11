from django.utils import timezone

from dashboard.models import SiemEvent
from dashboard.siem_query import parse_search_request, search_siem_events


def test_parse_search_request_multi_filters():
    params = parse_search_request(
        {
            "event_type_in": "a,b",
            "source_in": "x,y",
            "source_ip_in": "10.1.1.14,10.1.2.14",
            "destination_port_in": "502,4840",
            "agg": "source",
        }
    )
    assert params["event_type_in"] == ["a", "b"]
    assert params["source_in"] == ["x", "y"]
    assert params["source_ip_in"] == ["10.1.1.14", "10.1.2.14"]
    assert params["destination_port_in"] == [502, 4840]
    assert params["agg_fields"] == ["source"]


def test_search_siem_events_aggregations(db):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="suricata",
        event_type="suricata.alert",
        event_module="suricata",
        event_dataset="suricata.alert",
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
        destination_ip="10.1.1.10",
        network_community_id="1:abc123",
        summary="b",
        raw={},
    )

    params = {
        "agg_fields": ["source"],
        "agg_size": 10,
        "limit": 10,
        "offset": 0,
    }
    result = search_siem_events(params)
    assert result["count"] == 2
    assert result["aggregations"][0]["field"] == "source"
    assert len(result["aggregations"][0]["buckets"]) == 2


def test_search_siem_events_filters_on_canonical_network_fields(db):
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

    result = search_siem_events(
        {
            "event_module": "zeek",
            "event_dataset": "zeek.conn",
            "observer_name": "zeek-l1",
            "source_ip": "10.1.1.14",
            "source_port": 43100,
            "destination_ip": "10.1.1.10",
            "destination_port": 4840,
            "network_community_id": "1:abc123",
            "limit": 10,
            "offset": 0,
        }
    )

    assert result["count"] == 1
    assert result["results"][0]["event_module"] == "zeek"
    assert result["results"][0]["event_dataset"] == "zeek.conn"
    assert result["results"][0]["observer_name"] == "zeek-l1"
    assert result["results"][0]["source_port"] == 43100
    assert result["results"][0]["destination_port"] == 4840


def test_search_siem_events_filters_on_multi_value_network_fields(db):
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

    result = search_siem_events(
        {
            "source_ip_in": ["10.2.50.20", "10.1.1.10"],
            "destination_port_in": [44818],
            "limit": 10,
            "offset": 0,
        }
    )

    assert result["count"] == 1
    assert result["results"][0]["destination_port"] == 44818


def test_search_siem_events_excludes_stats_noise_when_requested(db):
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

    result = search_siem_events({"exclude_stats": True, "limit": 10, "offset": 0})

    assert result["count"] == 1
    assert result["results"][0]["event_dataset"] == "agent.network_connection"
