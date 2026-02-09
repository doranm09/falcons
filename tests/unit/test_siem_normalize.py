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


def test_normalize_siem_event_requires_type():
    with pytest.raises(SiemNormalizeError):
        normalize_siem_event({"source": "zeek"})


def test_normalize_siem_event_invalid_timestamp():
    with pytest.raises(SiemNormalizeError):
        normalize_siem_event({"event_type": "zeek.conn", "timestamp": "nope"})
