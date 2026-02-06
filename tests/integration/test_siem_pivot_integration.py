import pytest
from django.urls import reverse

from dashboard.models import Node, ScanRun, ScanVulnerability


@pytest.mark.django_db
def test_siem_pivot_returns_scan_url(client):
    scan = ScanRun.objects.create(cidr="10.0.0.0/24", status="COMPLETE", scan_type="ping")
    Node.objects.create(scan_run=scan, ip_address="10.0.0.8", name="node-d", status="online")
    ScanVulnerability.objects.create(
        scan_run=scan,
        host_ip="10.0.0.8",
        cve_id="CVE-2024-0004",
        name="Test",
        severity="Low",
    )

    resp = client.get(reverse("dashboard:siem_pivot_lookup"), {"asset_ip": "10.0.0.8"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["found"] is True
    assert body["scan_run_id"] == scan.id
    assert str(scan.id) in body["scan_url"]
