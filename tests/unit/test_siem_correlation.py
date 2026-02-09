from django.utils import timezone

from dashboard.models import Node, ScanRun, ScanVulnerability, Vulnerability
from dashboard.siem_correlation import resolve_asset_context


def test_resolve_asset_context_counts(db):
    scan_run = ScanRun.objects.create(cidr="10.0.0.0/24")
    node = Node.objects.create(
        scan_run=scan_run,
        ip_address="10.0.0.5",
        name="node-1",
        agent_id="agent-1",
    )
    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.5",
        cve_id="CVE-2024-0001",
        name="SSH Vuln",
    )
    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.5",
        cve_id="CVE-2024-0002",
        name="HTTP Vuln",
    )
    vuln1 = Vulnerability.objects.create(
        cve_id="CVE-2024-0101",
        description="Test vuln",
        severity="High",
        score=7.5,
        published=timezone.now(),
        last_modified=timezone.now(),
    )
    vuln2 = Vulnerability.objects.create(
        cve_id="CVE-2024-0102",
        description="Another vuln",
        severity="Low",
        score=3.0,
        published=timezone.now(),
        last_modified=timezone.now(),
    )
    vuln1.nodes.add(node)
    vuln2.nodes.add(node)

    context = resolve_asset_context({"asset_ip": "10.0.0.5"})

    assert context["node_id"] == node.id
    assert context["scan_run_id"] == scan_run.id
    assert context["scan_vuln_count"] == 2
    assert context["node_cve_count"] == 2


def test_resolve_asset_context_requires_asset(db):
    Node.objects.create(ip_address="10.0.0.6", name="node-2", agent_id="agent-2")

    context = resolve_asset_context({})

    assert context["node_id"] is None
    assert context["scan_run_id"] is None
    assert context["scan_vuln_count"] is None
    assert context["node_cve_count"] is None
