import json
import pytest

from django.core.management import call_command
from django.urls import reverse
from django.utils.timezone import now

from dashboard import views as dashboard_views
from dashboard import tasks as dashboard_tasks
from dashboard.models import Node, SbomReport, Vulnerability


pytestmark = pytest.mark.django_db


def test_sbom_ingest_creates_report_and_updates_node(agent_client, monkeypatch):
    agent_id = "agent-123"
    Node.objects.create(agent_id=agent_id, name="host1", ip_address="192.168.1.10")
    delay_mock = []
    monkeypatch.setattr(
        dashboard_views.scan_sbom_vulnerabilities_task,
        "delay",
        lambda **kwargs: delay_mock.append(kwargs),
    )

    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {"type": "operating-system", "name": "ubuntu", "version": "22.04"}
        },
        "components": [
            {"type": "application", "name": "openssl", "version": "1.1.1"},
            {"type": "application", "name": "curl", "version": "8.0.0"},
        ],
        "vulnerabilities": [
            {"id": "CVE-2024-0001", "severity": "High", "cvssScore": 7.5, "description": "Test CVE"},
            {"id": "CVE-2024-0002", "severity": "Low", "cvssScore": 3.1},
        ],
    }

    response = agent_client.post(
        reverse("dashboard:sbom_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
        **{"HTTP_X_AGENT_ID": agent_id},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "sbom_received"
    assert data["package_count"] == 2

    report = SbomReport.objects.get(id=data["sbom_id"])
    assert report.agent_id == agent_id
    assert report.format == "cyclonedx"
    assert report.package_count == 2
    assert report.os_summary == "ubuntu 22.04"
    assert delay_mock == [{"agent_id": agent_id, "report_id": report.id}]

    node = Node.objects.get(agent_id=agent_id)
    assert node.os_info == "ubuntu 22.04"
    assert "openssl@1.1.1" in node.installed_libraries

    vuln = Vulnerability.objects.get(cve_id="CVE-2024-0001")
    assert vuln.severity == "High"
    assert vuln.score == 7.5
    assert node.vulnerability_set.filter(cve_id="CVE-2024-0001").exists()


def test_sbom_ingest_requires_agent_id(agent_client):
    payload = {"components": []}
    response = agent_client.post(
        reverse("dashboard:sbom_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["error"] == "agent_id is required"


def test_sbom_ingest_accepts_raw_packages(agent_client):
    agent_id = "agent-raw"
    Node.objects.create(agent_id=agent_id, name="host2", ip_address="192.168.1.11")

    payload = {"agent_id": agent_id, "packages": ["nginx@1.24.0", "python@3.11"]}
    response = agent_client.post(
        reverse("dashboard:sbom_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["package_count"] == 2

    node = Node.objects.get(agent_id=agent_id)
    assert "nginx@1.24.0" in node.installed_libraries


def test_agent_cyber_report_updates_node_without_queuing_sbom_scan(agent_client, monkeypatch):
    agent_id = "agent-cyber"
    Node.objects.create(agent_id=agent_id, name="host-cyber", ip_address="192.168.1.12")
    delay_mock = []
    monkeypatch.setattr(
        dashboard_views.scan_sbom_vulnerabilities_task,
        "delay",
        lambda **kwargs: delay_mock.append(kwargs),
    )

    payload = {
        "agent_id": agent_id,
        "cyber_data": {
            "OS": "Ubuntu 24.04",
            "lib": ["python3@3.12.0", "curl@8.5.0"],
            "MAC": ["00:11:22:33:44:55"],
            "port": [{"id": "22", "state": "LISTEN"}],
        },
    }

    response = agent_client.post(
        reverse("dashboard:agent_cyber_report"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "cyber_data_updated"
    assert delay_mock == []


def test_scan_sbom_vulnerabilities_task_requires_stored_report():
    result = dashboard_tasks.scan_sbom_vulnerabilities_task.run(agent_id="missing-agent")
    assert result == {"status": "noop", "reason": "stored sbom report required"}


def test_scan_sbom_vulnerabilities_task_scans_stored_report(monkeypatch):
    agent_id = "agent-report-scan"
    node = Node.objects.create(agent_id=agent_id, name="host-scan", ip_address="192.168.1.13")
    report = SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="cyclonedx",
        bom_format="CycloneDX",
        spec_version="1.6",
        document={
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "openssl", "version": "3.0.13"}],
        },
        package_count=1,
        os_summary="Debian GNU/Linux 13 (trixie)",
        sha256="abc123",
    )

    monkeypatch.setattr(dashboard_tasks.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(dashboard_tasks, "_trivy_db_present", lambda: True)
    monkeypatch.setattr(dashboard_tasks, "_grype_db_present", lambda: True)

    scanner_calls = []

    persisted_vulns = []

    def fake_run_scanner(cmd, timeout_seconds, env=None):
        scanner_calls.append({"cmd": cmd, "timeout": timeout_seconds, "env": env})
        if cmd[0].endswith("trivy"):
            return (
                {
                    "Results": [
                        {
                            "Target": "openssl",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2024-1111",
                                    "PkgName": "openssl",
                                    "InstalledVersion": "3.0.13",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ]
                },
                "",
            )
        return (
            {
                "matches": [
                    {
                        "artifact": {"name": "curl", "version": "8.5.0"},
                        "vulnerability": {
                            "id": "CVE-2024-2222",
                            "severity": "High",
                            "dataSource": "https://security-tracker.debian.org/tracker/CVE-2024-2222",
                            "fix": {"versions": ["8.5.1"]},
                            "cvss": [
                                {
                                    "version": "3.1",
                                    "metrics": {"baseScore": 7.5},
                                }
                            ],
                        },
                    }
                ]
            },
            "",
        )

    monkeypatch.setattr(dashboard_tasks, "_run_scanner", fake_run_scanner)
    monkeypatch.setattr(
        dashboard_tasks,
        "_persist_scanner_vulnerabilities",
        lambda _node, vulns: persisted_vulns.extend(vulns) or len(vulns),
    )

    result = dashboard_tasks.scan_sbom_vulnerabilities_task.run(agent_id=agent_id, report_id=report.id)

    assert result["status"] == "ok"
    assert result["report_id"] == report.id
    assert result["packages"] == 1
    assert result["findings"] == 2
    assert result["persisted"] == 2
    assert any("--skip-db-update" in call["cmd"] for call in scanner_calls if call["cmd"][0].endswith("trivy"))
    assert any(call["env"] and call["env"].get("GRYPE_DB_AUTO_UPDATE") == "false" for call in scanner_calls if call["cmd"][0].endswith("grype"))
    assert any("--distro" in call["cmd"] and "debian:13" in call["cmd"] for call in scanner_calls if call["cmd"][0].endswith("grype"))
    grype_vuln = next(vuln for vuln in persisted_vulns if vuln["cve_id"] == "CVE-2024-2222")
    assert grype_vuln["package"] == "curl"
    assert grype_vuln["installed_version"] == "8.5.0"
    assert grype_vuln["fixed_version"] == "8.5.1"
    assert grype_vuln["source"] == "https://security-tracker.debian.org/tracker/CVE-2024-2222"
    assert grype_vuln["score"] == 7.5
    report.refresh_from_db()
    assert report.scan_metadata["scanner_runs"]
    assert report.scan_metadata["findings_by_scanner"]["grype"][0]["package"] == "curl"


def test_backfill_sbom_vulnerability_context_command_updates_blank_rows(monkeypatch):
    agent_id = "agent-backfill"
    node = Node.objects.create(agent_id=agent_id, name="host-backfill", ip_address="192.168.1.14")
    report = SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="cyclonedx",
        bom_format="CycloneDX",
        spec_version="1.6",
        document={
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "curl", "version": "8.5.0"}],
        },
        package_count=1,
        os_summary="Debian GNU/Linux 13 (trixie)",
        sha256="backfill123",
    )
    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-3333",
        description="Needs backfill",
        severity="High",
        published=now(),
        last_modified=now(),
    )
    node.vulnerability_set.add(vuln)

    monkeypatch.setattr(dashboard_tasks.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(dashboard_tasks, "_trivy_db_present", lambda: False)
    monkeypatch.setattr(dashboard_tasks, "_grype_db_present", lambda: True)

    def fake_run_scanner(cmd, timeout_seconds, env=None):
        if cmd[0].endswith("grype"):
            return (
                {
                    "matches": [
                        {
                            "artifact": {"name": "curl", "version": "8.5.0"},
                            "vulnerability": {
                                "id": "CVE-2024-3333",
                                "severity": "High",
                                "dataSource": "https://security-tracker.debian.org/tracker/CVE-2024-3333",
                                "fix": {"versions": ["8.5.1"]},
                                "cvss": [{"metrics": {"baseScore": 8.1}}],
                            },
                        }
                    ]
                },
                "",
            )
        return None, "scanner unavailable"

    monkeypatch.setattr(dashboard_tasks, "_run_scanner", fake_run_scanner)

    call_command("backfill_sbom_vulnerability_context", agent_id=agent_id)

    vuln.refresh_from_db()
    assert vuln.package == "curl"
    assert vuln.installed_version == "8.5.0"
    assert vuln.fixed_version == "8.5.1"
    assert vuln.source == "https://security-tracker.debian.org/tracker/CVE-2024-3333"
    assert vuln.score == 8.1
    assert report.id is not None
