import json
from datetime import datetime, timezone

from dashboard.opensearch_client import build_index_name, build_bulk_payload


def _bulk_document(payload: str) -> dict:
    action, document = payload.strip().splitlines()
    assert json.loads(action)["index"]["_index"].startswith("siem-events-")
    return json.loads(document)


def test_build_index_name_from_datetime():
    ts = datetime(2026, 2, 6, 12, 0, tzinfo=timezone.utc)
    assert build_index_name("siem-events", ts) == "siem-events-2026.02.06"


def test_build_bulk_payload_contains_index():
    payload = build_bulk_payload(
        [
            {
                "timestamp": "2026-02-06T12:00:00Z",
                "event_type": "suricata.alert",
                "source": "suricata",
                "event_module": "suricata",
                "event_dataset": "suricata.alert",
                "observer_name": "suricata-l1",
                "source_ip": "10.1.1.14",
                "source_port": 43000,
                "destination_ip": "10.1.1.10",
                "destination_port": 502,
                "network_community_id": "1:abc123",
                "summary": "alert",
                "raw": {"alert": True},
            }
        ],
        "siem-events",
    )
    document = _bulk_document(payload)

    assert document["event_type"] == "suricata.alert"
    assert document["event_source"] == "suricata"
    assert document["event_module"] == "suricata"
    assert document["event_dataset"] == "suricata.alert"
    assert document["observer_name"] == "suricata-l1"
    assert document["source_ip"] == "10.1.1.14"
    assert document["source_port"] == 43000
    assert document["destination_ip"] == "10.1.1.10"
    assert document["destination_port"] == 502
    assert document["network_community_id"] == "1:abc123"
    assert document["source"]["ip"] == "10.1.1.14"
    assert document["source"]["port"] == 43000
    assert document["destination"]["ip"] == "10.1.1.10"
    assert document["destination"]["port"] == 502


def test_build_bulk_payload_falls_back_to_dotted_zeek_keys():
    payload = build_bulk_payload(
        [
            {
                "timestamp": "2026-02-06T12:00:00Z",
                "event_type": "zeek.conn",
                "source": "zeek",
                "summary": "conn",
                "raw": {
                    "event": {"module": "zeek", "dataset": "zeek.conn"},
                    "observer": {"name": "zeek-l1"},
                    "id.orig_h": "10.1.1.14",
                    "id.orig_p": 43100,
                    "id.resp_h": "10.1.1.10",
                    "id.resp_p": 4840,
                },
            }
        ],
        "siem-events",
    )
    document = _bulk_document(payload)

    assert document["event_source"] == "zeek"
    assert document["event_module"] == "zeek"
    assert document["event_dataset"] == "zeek.conn"
    assert document["source_ip"] == "10.1.1.14"
    assert document["source_port"] == 43100
    assert document["destination_ip"] == "10.1.1.10"
    assert document["destination_port"] == 4840
    assert document["source"]["ip"] == "10.1.1.14"
    assert document["source"]["port"] == 43100
    assert document["destination"]["ip"] == "10.1.1.10"
    assert document["destination"]["port"] == 4840
