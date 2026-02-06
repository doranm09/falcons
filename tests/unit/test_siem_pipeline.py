import pytest

from dashboard.siem_pipeline import transform_pipeline_event, SiemPipelineError


def test_transform_suricata_payload():
    payload = {
        "alert": {"signature": "ET MALWARE Example", "severity": 2},
        "src_ip": "10.1.1.10",
        "timestamp": "2026-02-06T12:05:00Z",
    }
    event = transform_pipeline_event(payload)
    assert event["event_type"] == "suricata.alert"
    assert event["source"] == "suricata"
    assert event["asset_ip"] == "10.1.1.10"
    assert event["message"] == "ET MALWARE Example"


def test_transform_zeek_payload_epoch_ts():
    payload = {
        "uid": "C1",
        "id_orig_h": "10.1.1.11",
        "ts": 1760088000,
    }
    event = transform_pipeline_event(payload)
    assert event["event_type"].startswith("zeek")
    assert event["source"] == "zeek"
    assert event["timestamp"].endswith("+00:00")


def test_transform_invalid_payload():
    with pytest.raises(SiemPipelineError):
        transform_pipeline_event("bad")
