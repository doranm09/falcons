import json

import pytest
from django.urls import reverse

from dashboard.models import Alert, AlertRule, ThreatIntelMatch


@pytest.mark.django_db
def test_threat_intel_enrichment_in_alerts(client):
    client.post(
        reverse("dashboard:siem_threat_intel_ingest"),
        data=json.dumps({"indicators": [{"indicator_type": "ip", "value": "10.10.0.13"}]}),
        content_type="application/json",
    )

    rule, _ = AlertRule.objects.get_or_create(
        name="Suricata Alerts",
        defaults={
            "rule_type": "suricata",
            "enabled": True,
            "match_event_type": "suricata.alert",
            "match_source": "suricata",
            "suppression_minutes": 0,
        },
    )
    if not rule.enabled or rule.match_event_type != "suricata.alert":
        rule.enabled = True
        rule.match_event_type = "suricata.alert"
        rule.match_source = "suricata"
        rule.suppression_minutes = 0
        rule.save(update_fields=["enabled", "match_event_type", "match_source", "suppression_minutes"])

    event_payload = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "timestamp": "2026-02-06T12:40:00Z",
        "message": "ET MALWARE",
        "asset_ip": "10.10.0.13",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(event_payload),
        content_type="application/json",
    )
    assert resp.status_code == 201

    alert = Alert.objects.first()
    assert "IOC" in alert.summary
    assert ThreatIntelMatch.objects.count() == 1
