import json

import pytest
from django.urls import reverse

from dashboard.models import Alert, AlertRule


@pytest.mark.django_db
def test_alert_deduplication(client):
    rule, _ = AlertRule.objects.get_or_create(
        name="Suricata Alerts",
        defaults={
            "rule_type": "suricata",
            "enabled": True,
            "match_event_type": "suricata.alert",
            "match_source": "suricata",
            "suppression_minutes": 10,
        },
    )
    if not rule.enabled or rule.match_event_type != "suricata.alert":
        rule.enabled = True
        rule.match_event_type = "suricata.alert"
        rule.match_source = "suricata"
        rule.suppression_minutes = 10
        rule.save(update_fields=["enabled", "match_event_type", "match_source", "suppression_minutes"])

    payload = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "timestamp": "2026-02-06T12:21:00Z",
        "message": "ET MALWARE",
        "asset_ip": "10.10.0.10",
    }

    resp1 = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp1.status_code == 201
    resp2 = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp2.status_code == 201

    alert = Alert.objects.first()
    assert Alert.objects.count() == 1
    assert alert.count == 2
