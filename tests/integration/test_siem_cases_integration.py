import json

import pytest
from django.urls import reverse

from dashboard.models import Alert, AlertRule, Case


@pytest.mark.django_db
def test_alert_to_case_flow(siem_analyst_client):
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
    payload = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "timestamp": "2026-02-06T12:30:00Z",
        "message": "ET MALWARE",
        "asset_ip": "10.10.0.11",
    }
    siem_analyst_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    alert = Alert.objects.first()
    resp = siem_analyst_client.post(reverse("dashboard:siem_case_promote_alert", args=[alert.id]))
    assert resp.status_code == 302
    case = Case.objects.first()
    assert case.alerts.count() == 1
