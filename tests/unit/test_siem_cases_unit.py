from django.utils import timezone

from dashboard.models import Alert, Case
from dashboard.siem_cases import build_case_from_alert, export_case_payload


def test_build_case_from_alert():
    alert = Alert(
        rule_name="Rule",
        event_type="suricata.alert",
        source="suricata",
        summary="Example",
        asset_ip="10.0.0.10",
    )
    case = build_case_from_alert(alert)
    assert "Rule" in case.title
    assert "10.0.0.10" in case.title


def test_export_case_payload(db):
    case = Case.objects.create(title="Case 1", description="Test")
    payload = export_case_payload(case)
    assert payload["title"] == "Case 1"
    assert payload["alerts"] == []
