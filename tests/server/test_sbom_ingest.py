import json
import pytest

from django.urls import reverse

from dashboard.models import Node, SbomReport, Vulnerability


pytestmark = pytest.mark.django_db


def test_sbom_ingest_creates_report_and_updates_node(client):
    agent_id = "agent-123"
    Node.objects.create(agent_id=agent_id, name="host1", ip_address="192.168.1.10")

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

    response = client.post(
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

    node = Node.objects.get(agent_id=agent_id)
    assert node.os_info == "ubuntu 22.04"
    assert "openssl@1.1.1" in node.installed_libraries

    vuln = Vulnerability.objects.get(cve_id="CVE-2024-0001")
    assert vuln.severity == "High"
    assert vuln.score == 7.5
    assert node.vulnerability_set.filter(cve_id="CVE-2024-0001").exists()


def test_sbom_ingest_requires_agent_id(client):
    payload = {"components": []}
    response = client.post(
        reverse("dashboard:sbom_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["error"] == "agent_id is required"


def test_sbom_ingest_accepts_raw_packages(client):
    agent_id = "agent-raw"
    Node.objects.create(agent_id=agent_id, name="host2", ip_address="192.168.1.11")

    payload = {"agent_id": agent_id, "packages": ["nginx@1.24.0", "python@3.11"]}
    response = client.post(
        reverse("dashboard:sbom_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["package_count"] == 2

    node = Node.objects.get(agent_id=agent_id)
    assert "nginx@1.24.0" in node.installed_libraries
