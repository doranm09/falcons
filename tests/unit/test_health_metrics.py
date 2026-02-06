import pytest
from django.test import override_settings

from dashboard.health import health_snapshot, metrics_payload


@pytest.mark.django_db
@override_settings(OPENSEARCH_ENABLED=False)
def test_health_snapshot_structure():
    snapshot = health_snapshot()
    assert snapshot["status"] in {"ok", "degraded"}
    assert "checks" in snapshot
    assert "database" in snapshot["checks"]
    assert "opensearch" in snapshot["checks"]


@pytest.mark.django_db
@override_settings(OPENSEARCH_ENABLED=False)
def test_metrics_payload_includes_counts():
    payload = metrics_payload()
    assert "cybertwin_siem_events_total" in payload
    assert "cybertwin_service_up" in payload
