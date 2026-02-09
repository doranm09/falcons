import json

import pytest
from django.urls import reverse

from dashboard.models import Alert, AlertRule


@pytest.mark.django_db
def test_siem_ingest_creates_alert(siem_client):
    rule = AlertRule.objects.create(
        name="Sigma Rule",
        rule_type="sigma",
        enabled=True,
        match_event_type="zeek.conn",
        match_source="zeek",
        match_contains="conn",
        suppression_minutes=0,
    )
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:20:00Z",
        "message": "conn observed",
    }
    resp = siem_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert Alert.objects.count() == 1


@pytest.mark.django_db
def test_toggle_rule(siem_admin_client):
    rule = AlertRule.objects.create(name="Rule", rule_type="sigma", enabled=True)
    resp = siem_admin_client.post(reverse("dashboard:siem_toggle_rule", args=[rule.id]))
    assert resp.status_code == 302
    rule.refresh_from_db()
    assert rule.enabled is False
