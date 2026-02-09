from datetime import datetime, timezone

from dashboard.opensearch_client import build_index_name, build_bulk_payload


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
                "summary": "alert",
                "raw": {"alert": True},
            }
        ],
        "siem-events",
    )
    assert "siem-events-2026.02.06" in payload
    assert "\"event_type\": \"suricata.alert\"" in payload
