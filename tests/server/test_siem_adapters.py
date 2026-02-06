import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import AgentStatus, Node, SbomReport, ScanRun, Vulnerability


@pytest.mark.django_db
def test_siem_adapter_agent_endpoint(client):
    agent = AgentStatus.objects.create(
        agent_id="agent-01",
        hostname="host-a",
        ip_address="10.0.0.1",
        status="online",
        last_heartbeat=timezone.now(),
    )
    resp = client.get(reverse("dashboard:siem_adapter_agent", args=[agent.agent_id]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_type"] == "agent.heartbeat"
    assert "@timestamp" in body


@pytest.mark.django_db
def test_siem_adapter_vulnerability_endpoint(client):
    node = Node.objects.create(ip_address="10.0.0.2", name="node-a", status="online")
    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-0001",
        description="Test",
        severity="Medium",
        score=5.0,
        published=timezone.now(),
        last_modified=timezone.now(),
        references="",
    )
    resp = client.get(
        reverse("dashboard:siem_adapter_vulnerability", args=[vuln.id]),
        {"node_id": node.id},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_type"] == "vulnerability.detected"
    assert body["rule"]["id"] == "CVE-2024-0001"


@pytest.mark.django_db
def test_siem_adapter_scan_endpoint(client):
    scan = ScanRun.objects.create(
        cidr="10.0.0.0/24",
        status="COMPLETE",
        scan_type="ping",
        timestamp=timezone.now(),
    )
    resp = client.get(reverse("dashboard:siem_adapter_scan", args=[scan.id]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_type"] == "scan.run"
    assert body["labels"]["scan_id"] == scan.id


@pytest.mark.django_db
def test_siem_adapter_sbom_endpoint(client):
    node = Node.objects.create(ip_address="10.0.0.3", name="node-b", status="online", agent_id="agent-02")
    report = SbomReport.objects.create(
        node=node,
        agent_id="agent-02",
        document={},
        package_count=3,
        format="cyclonedx",
        bom_format="CycloneDX",
        spec_version="1.4",
        sha256="abc",
    )
    resp = client.get(reverse("dashboard:siem_adapter_sbom", args=[report.id]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_type"] == "sbom.report"
    assert body["labels"]["package_count"] == 3
