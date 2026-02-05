import requests
import pytest

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from dashboard.models import Node, ScanRun, ScanVulnerability, Vulnerability


def _risk_url(path: str) -> str:
    base = settings.RISK_ASSESSMENT_API_URL.rstrip("/")
    return f"{base}/{path.lstrip('/')}"


def _risk_service_available() -> bool:
    try:
        response = requests.get(_risk_url("/status"), timeout=2)
        return response.ok
    except Exception:
        return False


@pytest.mark.django_db
def test_risk_assessment_network_compute_integration(client):
    if not _risk_service_available():
        pytest.skip("Risk assessment service unavailable.")

    nodes_response = requests.get(_risk_url("/nodes"), timeout=5)
    if not nodes_response.ok:
        pytest.skip("Risk assessment nodes endpoint unavailable.")

    payload = nodes_response.json()
    variables = payload.get("variables", {})
    risk_nodes = list(variables.keys())
    if not risk_nodes:
        pytest.skip("Risk assessment returned no nodes.")

    scan_run = ScanRun.objects.create(cidr="10.99.0.0/24")
    for index, risk_node_id in enumerate(risk_nodes[:2]):
        ip_address = f"10.99.0.{index + 10}"
        node = Node.objects.create(name=risk_node_id, ip_address=ip_address)
        vuln = Vulnerability.objects.create(
            cve_id=f"CVE-2024-10{index}",
            description="Integration test vuln",
            severity="Medium",
            score=5.0,
            published=timezone.now(),
            last_modified=timezone.now(),
        )
        vuln.nodes.add(node)
        ScanVulnerability.objects.create(
            scan_run=scan_run,
            host_ip=ip_address,
            cve_id=f"CVE-2024-20{index}",
            name="Integration scan vuln",
            severity="Low",
            cvss_score=3.2,
        )

    response = client.get(reverse("dashboard:risk_assessment_network_compute"))
    assert response.status_code == 200

    data = response.json()
    assert "results" in data
    assert "mapped_nodes" in data

    mapped = {entry["risk_node_id"]: entry for entry in data["mapped_nodes"] if entry["risk_node_id"]}
    for risk_node_id in risk_nodes[:2]:
        assert risk_node_id in mapped
