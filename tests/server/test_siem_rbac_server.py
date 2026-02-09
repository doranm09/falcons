import pytest
from django.urls import reverse

from dashboard.models import AlertRule


@pytest.mark.django_db
def test_rbac_denies_toggle_for_anonymous(client):
    rule = AlertRule.objects.create(name="Rule", rule_type="sigma", enabled=True)
    resp = client.post(reverse("dashboard:siem_toggle_rule", args=[rule.id]))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_rbac_allows_toggle_for_admin(siem_admin_client):
    rule = AlertRule.objects.create(name="Rule2", rule_type="sigma", enabled=True)
    resp = siem_admin_client.post(reverse("dashboard:siem_toggle_rule", args=[rule.id]))
    assert resp.status_code == 302
