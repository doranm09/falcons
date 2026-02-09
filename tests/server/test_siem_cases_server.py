import pytest
from django.urls import reverse

from dashboard.models import Alert, AlertRule, Case


@pytest.mark.django_db
def test_promote_alert_to_case(siem_analyst_client):
    rule = AlertRule.objects.create(name="Rule", rule_type="sigma", enabled=True)
    alert = Alert.objects.create(
        rule=rule,
        rule_name="Rule",
        rule_type="sigma",
        event_type="zeek.conn",
        source="zeek",
        summary="Conn",
        dedup_key="1",
    )
    resp = siem_analyst_client.post(reverse("dashboard:siem_case_promote_alert", args=[alert.id]))
    assert resp.status_code == 302
    assert Case.objects.count() == 1


@pytest.mark.django_db
def test_case_create_and_export(siem_analyst_client):
    resp = siem_analyst_client.post(
        reverse("dashboard:siem_case_create"),
        {"title": "Case Title", "description": "Desc", "priority": "low"},
    )
    assert resp.status_code == 302
    case = Case.objects.first()
    export_resp = siem_analyst_client.get(reverse("dashboard:siem_case_export", args=[case.id]))
    assert export_resp.status_code == 200
    assert b"Case Title" in export_resp.content
