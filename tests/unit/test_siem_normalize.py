import pytest

from dashboard.siem import normalize_siem_event, SiemNormalizeError


def test_normalize_siem_event_minimal():
    payload = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "timestamp": "2026-02-06T12:00:00Z",
        "message": "ET MALWARE Example",
        "host": {"ip": ["10.1.2.3"]},
        "severity": "4",
    }

    result = normalize_siem_event(payload)

    assert result["event_type"] == "suricata.alert"
    assert result["source"] == "suricata"
    assert result["asset_ip"] == "10.1.2.3"
    assert result["severity"] == 4
    assert result["summary"] == "ET MALWARE Example"
    assert result["event_module"] == ""
    assert result["event_dataset"] == ""


def test_normalize_siem_event_extracts_network_fields():
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:00:00Z",
        "raw": {
            "event": {"module": "zeek", "dataset": "zeek.conn"},
            "observer": {"name": "zeek-l1"},
            "id_orig_h": "10.1.1.14",
            "id_orig_p": 43000,
            "id_resp_h": "10.1.1.10",
            "id_resp_p": 502,
            "network": {"community_id": "1:abc123"},
        },
    }

    result = normalize_siem_event(payload)

    assert result["event_module"] == "zeek"
    assert result["event_dataset"] == "zeek.conn"
    assert result["observer_name"] == "zeek-l1"
    assert result["source_ip"] == "10.1.1.14"
    assert result["source_port"] == 43000
    assert result["destination_ip"] == "10.1.1.10"
    assert result["destination_port"] == 502
    assert result["network_community_id"] == "1:abc123"


def test_normalize_siem_event_extracts_dotted_zeek_ip_fields():
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:00:00Z",
        "raw": {
            "event": {"module": "zeek", "dataset": "zeek.conn"},
            "observer": {"name": "zeek-l1"},
            "id.orig_h": "10.1.1.14",
            "id.orig_p": 43100,
            "id.resp_h": "10.1.1.10",
            "id.resp_p": 4840,
        },
    }

    result = normalize_siem_event(payload)

    assert result["asset_ip"] == "10.1.1.14"
    assert result["source_ip"] == "10.1.1.14"
    assert result["source_port"] == 43100
    assert result["destination_ip"] == "10.1.1.10"
    assert result["destination_port"] == 4840


def test_normalize_siem_event_requires_type():
    with pytest.raises(SiemNormalizeError):
        normalize_siem_event({"source": "zeek"})


def test_normalize_siem_event_invalid_timestamp():
    with pytest.raises(SiemNormalizeError):
        normalize_siem_event({"event_type": "zeek.conn", "timestamp": "nope"})
