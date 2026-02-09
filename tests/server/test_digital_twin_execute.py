import json
import os
import subprocess
import pytest

from django.urls import reverse

from dashboard.models import ScanRun, Node, Link


pytestmark = pytest.mark.django_db


def _create_scan():
    scan = ScanRun.objects.create(cidr="10.0.0.0/24", status="COMPLETE")
    node1 = Node.objects.create(scan_run=scan, ip_address="10.0.0.10", name="web-1")
    node2 = Node.objects.create(scan_run=scan, ip_address="10.0.0.11", name="db-1")
    Link.objects.create(scan_run=scan, source=node1, destination=node2, weight=1.0)
    return scan


def test_digital_twin_execute_disabled(client, tmp_path, monkeypatch):
    scan = _create_scan()
    disk = tmp_path / "base.qcow2"
    disk.write_text("fake")

    payload = {
        "scan_id": scan.id,
        "disk_image": str(disk),
        "confirm": "RUN_MINIMEGA",
    }

    monkeypatch.delenv("MINIMEGA_EXECUTION_ENABLED", raising=False)
    response = client.post(
        reverse("dashboard:digital_twin_execute"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 403


def test_digital_twin_execute_success(client, tmp_path, monkeypatch):
    scan = _create_scan()
    disk = tmp_path / "base.qcow2"
    disk.write_text("fake")

    payload = {
        "scan_id": scan.id,
        "disk_image": str(disk),
        "confirm": "RUN_MINIMEGA",
    }

    monkeypatch.setenv("MINIMEGA_EXECUTION_ENABLED", "1")

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    response = client.post(
        reverse("dashboard:digital_twin_execute"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "executed"
    assert data["returncode"] == 0
