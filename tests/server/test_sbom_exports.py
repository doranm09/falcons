import json
import pytest

from django.urls import reverse
from django.utils.timezone import now

from dashboard.models import Node, SbomReport, Vulnerability


pytestmark = pytest.mark.django_db


def test_sbom_export_json(client):
    agent_id = "agent-json"
    node = Node.objects.create(agent_id=agent_id, name="host", ip_address="10.0.0.5")
    report = SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="cyclonedx",
        document={"components": [{"name": "nginx", "version": "1.24.0"}]},
        package_count=1,
        os_summary="ubuntu 22.04",
        sha256="abc",
    )

    response = client.get(reverse("dashboard:agent_sbom_export", args=[agent_id]) + "?format=json")
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == agent_id
    assert data["package_count"] == 1
    assert data["document"]["components"][0]["name"] == "nginx"


def test_sbom_export_csv(client):
    agent_id = "agent-csv"
    node = Node.objects.create(agent_id=agent_id, name="host", ip_address="10.0.0.6")
    SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="raw",
        document={"packages": ["python@3.11", "openssl@1.1.1"]},
        package_count=2,
        os_summary="",
        sha256="def",
    )

    response = client.get(reverse("dashboard:agent_sbom_export", args=[agent_id]) + "?format=csv")
    assert response.status_code == 200
    body = response.content.decode("utf-8")
    assert "package" in body.splitlines()[0]
    assert "python@3.11" in body
    assert "openssl@1.1.1" in body


def test_sbom_diff(client):
    agent_id = "agent-diff"
    node = Node.objects.create(agent_id=agent_id, name="host", ip_address="10.0.0.7")

    SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="raw",
        document={"packages": ["a@1", "b@1"]},
        package_count=2,
        os_summary="",
        sha256="1",
    )
    SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="raw",
        document={"packages": ["b@1", "c@2"]},
        package_count=2,
        os_summary="",
        sha256="2",
    )

    response = client.get(reverse("dashboard:agent_sbom_diff", args=[agent_id]))
    assert response.status_code == 200
    data = response.json()
    assert "c@2" in data["added"]
    assert "a@1" in data["removed"]


def test_sbom_table_view_falls_back_to_persisted_vulnerabilities(client):
    agent_id = "agent-table-vuln"
    node = Node.objects.create(agent_id=agent_id, name="host", ip_address="10.0.0.8")
    node.installed_libraries = ["openssl@3.0.13"]
    node.save(update_fields=["installed_libraries"])
    report = SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="cyclonedx",
        document={"components": [{"name": "openssl", "version": "3.0.13"}]},
        package_count=1,
        os_summary="ubuntu 24.04",
        sha256="ghi",
    )
    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-1111",
        description="Persisted scanner finding",
        severity="High",
        score=7.5,
        package="openssl",
        installed_version="3.0.13",
        fixed_version="3.0.14",
        source="debian",
        published=now(),
        last_modified=now(),
    )
    node.vulnerability_set.add(vuln)

    response = client.get(reverse("dashboard:agent_sbom_export", args=[agent_id]) + "?format=table")

    assert response.status_code == 200
    body = response.content.decode("utf-8")
    assert "CVE-2024-1111" in body
    assert "openssl" in body
    assert "3.0.13" in body
    assert "3.0.14" in body
    assert "debian" in body
    assert report.agent_id == agent_id


def test_sbom_table_view_renders_scanner_tabs_and_sort_controls(client):
    agent_id = "agent-table-tabs"
    node = Node.objects.create(agent_id=agent_id, name="host", ip_address="10.0.0.9")
    SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format="cyclonedx",
        document={"components": [{"name": "curl", "version": "8.5.0"}]},
        scan_metadata={
            "scanner_runs": [
                {"scanner": "grype", "status": "ok", "findings": 1},
                {"scanner": "trivy", "status": "ok", "findings": 1},
            ],
            "findings_by_scanner": {
                "grype": [
                    {
                        "cve_id": "CVE-2024-2000",
                        "package": "curl",
                        "installed_version": "8.5.0",
                        "fixed_version": "8.5.1",
                        "severity": "High",
                        "score": 7.5,
                        "source": "https://security-tracker.debian.org/tracker/CVE-2024-2000",
                        "description": "Grype finding",
                        "references": "",
                    }
                ],
                "trivy": [
                    {
                        "cve_id": "CVE-2024-3000",
                        "package": "curl",
                        "installed_version": "8.5.0",
                        "fixed_version": "8.5.2",
                        "severity": "Critical",
                        "score": 9.8,
                        "source": "trivy-db",
                        "description": "Trivy finding",
                        "references": "",
                    }
                ],
            },
        },
        package_count=1,
        os_summary="debian 13",
        sha256="tabs123",
    )

    response = client.get(reverse("dashboard:agent_sbom_export", args=[agent_id]) + "?format=table")

    assert response.status_code == 200
    body = response.content.decode("utf-8")
    assert "All Findings" in body
    assert "Grype" in body
    assert "Trivy" in body
    assert "table-sort" in body
