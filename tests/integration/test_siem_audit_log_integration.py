import pytest
from django.urls import reverse

from dashboard.models import SiemAuditLog


@pytest.mark.django_db
def test_audit_log_records_hunt_create(siem_admin_client):
    resp = siem_admin_client.post(
        reverse("dashboard:siem_hunt_create"),
        data={"name": "Audit Hunt", "description": "Audit", "tags": "audit"},
    )
    assert resp.status_code == 302
    assert SiemAuditLog.objects.filter(action="siem_hunt_create").exists()

    audit_resp = siem_admin_client.get(
        reverse("dashboard:siem_audit_log") + "?format=json"
    )
    assert audit_resp.status_code == 200
    body = audit_resp.json()
    assert body["count"] >= 1
    actions = {entry["action"] for entry in body["results"]}
    assert "siem_hunt_create" in actions
