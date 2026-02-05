import json
import pytest

from django.urls import reverse

from dashboard.models import Node, SbomReport


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

    response = client.get(reverse("dashboard:agent_sbom_export", args=[agent_id]))
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
