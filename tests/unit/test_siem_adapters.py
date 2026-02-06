from django.utils import timezone

from dashboard.models import AgentStatus, ScanRun, SbomReport, Vulnerability
from dashboard.siem_adapters import (
    adapt_agent_status,
    adapt_scan_run,
    adapt_sbom_report,
    adapt_vulnerability,
)


def test_adapt_agent_status_fields():
    agent = AgentStatus(
        agent_id="agent-01",
        hostname="host-a",
        ip_address="10.0.0.1",
        status="online",
        os_type="linux",
        os_version="1.0",
        platform="x86_64",
        last_heartbeat=timezone.now(),
    )
    event = adapt_agent_status(agent)
    assert event["event_type"] == "agent.heartbeat"
    assert event["source"] == "agent"
    assert event["event"]["action"] == "heartbeat"
    assert event["host"]["hostname"] == "host-a"
    assert event["agent"]["id"] == "agent-01"


def test_adapt_scan_run_outcome():
    scan = ScanRun(
        cidr="10.0.0.0/24",
        status="FAILED",
        scan_type="nmap",
        timestamp=timezone.now(),
    )
    event = adapt_scan_run(scan)
    assert event["event_type"] == "scan.run"
    assert event["event"]["outcome"] == "failure"


def test_adapt_vulnerability_severity_map():
    vuln = Vulnerability(
        cve_id="CVE-2024-9999",
        description="Test",
        severity="High",
        score=None,
        published=timezone.now(),
        last_modified=timezone.now(),
        references="",
    )
    event = adapt_vulnerability(vuln)
    assert event["event_type"] == "vulnerability.detected"
    assert event["event"]["severity"] == 7


def test_adapt_sbom_report_fields():
    report = SbomReport(
        agent_id="agent-02",
        document={},
        package_count=5,
        format="cyclonedx",
        bom_format="CycloneDX",
        spec_version="1.4",
        sha256="abc",
        created_at=timezone.now(),
    )
    event = adapt_sbom_report(report)
    assert event["event_type"] == "sbom.report"
    assert event["labels"]["package_count"] == 5
