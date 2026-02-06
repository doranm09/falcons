from dashboard.siem_threat_intel import parse_ioc_payload, ingest_indicators
from dashboard.models import ThreatIntelIndicator


def test_parse_misp_payload():
    payload = {
        "Event": {
            "Attribute": [
                {"type": "ip-src", "value": "10.10.0.10"},
                {"type": "domain", "value": "evil.example"},
            ]
        }
    }
    indicators = parse_ioc_payload(payload)
    assert len(indicators) == 2


def test_ingest_indicators(db):
    payload = {
        "indicators": [
            {"indicator_type": "ip", "value": "10.10.0.11", "source": "test"},
            {"indicator_type": "domain", "value": "evil.test", "source": "test"},
        ]
    }
    stats = ingest_indicators(payload)
    assert stats["created"] == 2
    assert ThreatIntelIndicator.objects.count() == 2
