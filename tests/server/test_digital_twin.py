import json

from django.urls import reverse

from dashboard.models import ScanRun, Node, Link, SbomReport


def _create_scan_with_nodes():
    scan = ScanRun.objects.create(cidr="192.168.1.0/24", status="COMPLETE")
    node1 = Node.objects.create(scan_run=scan, ip_address="192.168.1.10", name="web-1", agent_id="agent-1")
    node2 = Node.objects.create(scan_run=scan, ip_address="192.168.1.11", name="db-1", agent_id="agent-2")
    Link.objects.create(scan_run=scan, source=node1, destination=node2, weight=2.5)
    Link.objects.create(scan_run=scan, source=node2, destination=node1, weight=2.5)

    SbomReport.objects.create(
        node=node1,
        agent_id="agent-1",
        format="cyclonedx",
        document={"components": [{"name": "nginx", "version": "1.24.0"}]},
        package_count=1,
        os_summary="ubuntu 22.04",
        sha256="test",
    )
    return scan


def test_digital_twin_generate_requires_disk_image(client):
    scan = _create_scan_with_nodes()
    response = client.post(
        reverse("dashboard:digital_twin_generate"),
        data=json.dumps({"scan_id": scan.id}),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["error"] == "disk_image is required"


def test_digital_twin_generate_success(client):
    scan = _create_scan_with_nodes()
    payload = {
        "scan_id": scan.id,
        "disk_image": "/var/lib/minimega/images/base.qcow2",
        "vlan": "200",
        "enable_virtio": True,
        "memory_mb": 1024,
    }
    response = client.post(
        reverse("dashboard:digital_twin_generate"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "generated"
    assert data["node_count"] == 2
    assert data["link_count"] == 2
    assert "vm launch kvm" in data["script"]
    assert data["manifest"]["minimega"]["vlan"] == "200"
