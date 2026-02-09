import io
import json
import zipfile
import pytest

from django.urls import reverse

from dashboard.models import Node, SbomReport


pytestmark = pytest.mark.django_db


def test_sbom_bundle_contains_files(client):
    agent_id = "agent-bundle"
    node = Node.objects.create(agent_id=agent_id, name="host", ip_address="10.0.0.9")

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

    response = client.get(reverse("dashboard:agent_sbom_bundle", args=[agent_id]))
    assert response.status_code == 200

    content = b"".join(response.streaming_content)
    zip_content = io.BytesIO(content)
    with zipfile.ZipFile(zip_content) as zf:
        names = zf.namelist()
        assert "sbom.json" in names
        assert "sbom.csv" in names
        assert "diff.json" in names

        diff = json.loads(zf.read("diff.json").decode("utf-8"))
        assert "c@2" in diff["added"]
        assert "a@1" in diff["removed"]
