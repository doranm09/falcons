from django.utils import timezone

from dashboard.models import Node, ScanRun, ScanVulnerability, Vulnerability
from dashboard.siem_pivot import resolve_siem_pivot


def test_resolve_siem_pivot_by_ip(db):
    scan = ScanRun.objects.create(cidr="10.0.0.0/24", status="COMPLETE", scan_type="ping")
    node = Node.objects.create(scan_run=scan, ip_address="10.0.0.5", name="node-a", status="online")
    result = resolve_siem_pivot("10.0.0.5", None)
    assert result["node_id"] == node.id


def test_resolve_siem_pivot_counts(db):
    scan = ScanRun.objects.create(cidr="10.0.0.0/24", status="COMPLETE", scan_type="ping")
    node = Node.objects.create(scan_run=scan, ip_address="10.0.0.6", name="node-b", status="online")
    ScanVulnerability.objects.create(
        scan_run=scan,
        host_ip="10.0.0.6",
        cve_id="CVE-2024-0002",
        name="Test",
        severity="Low",
    )
    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-0003",
        description="Test",
        severity="Medium",
        score=5.0,
        published=timezone.now(),
        last_modified=timezone.now(),
        references="",
    )
    vuln.nodes.add(node)
    result = resolve_siem_pivot("10.0.0.6", None)
    assert result["scan_vuln_count"] == 1
    assert result["node_cve_count"] == 1
