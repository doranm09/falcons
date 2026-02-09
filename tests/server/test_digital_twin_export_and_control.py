import json
import io
import zipfile
import subprocess
import pytest

from django.contrib.auth import get_user_model
from django.urls import reverse

from dashboard.models import ScanRun, Node, Link


pytestmark = pytest.mark.django_db


def _create_scan():
    scan = ScanRun.objects.create(cidr="10.10.0.0/24", status="COMPLETE")
    node1 = Node.objects.create(scan_run=scan, ip_address="10.10.0.10", name="web-1")
    node2 = Node.objects.create(scan_run=scan, ip_address="10.10.0.11", name="db-1")
    Link.objects.create(scan_run=scan, source=node1, destination=node2, weight=1.2)
    return scan


def test_digital_twin_export_bundle(client):
    scan = _create_scan()
    payload = {
        "scan_id": scan.id,
        "disk_image": "/var/lib/minimega/images/base.qcow2",
        "vlan": "100",
        "memory_mb": 1024,
    }

    response = client.post(
        reverse("dashboard:digital_twin_export"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    content = b"".join(response.streaming_content)
    zip_content = io.BytesIO(content)
    with zipfile.ZipFile(zip_content) as zf:
        names = zf.namelist()
        assert any(name.endswith(".mm") for name in names)
        assert "manifest.json" in names


def test_minimega_reset_requires_auth(client, monkeypatch):
    monkeypatch.setenv("MINIMEGA_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("MINIMEGA_ALLOW_RESET", "1")

    response = client.post(
        reverse("dashboard:digital_twin_reset"),
        data=json.dumps({"confirm": "RESET_MINIMEGA"}),
        content_type="application/json",
    )

    assert response.status_code == 401


def test_minimega_reset_staff_success(client, monkeypatch):
    User = get_user_model()
    user = User.objects.create_user(username="staff", password="pass", is_staff=True)
    client.force_login(user)

    monkeypatch.setenv("MINIMEGA_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("MINIMEGA_ALLOW_RESET", "1")

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="reset", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    response = client.post(
        reverse("dashboard:digital_twin_reset"),
        data=json.dumps({"confirm": "RESET_MINIMEGA"}),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "reset"


def test_minimega_kill_staff_success(client, monkeypatch):
    User = get_user_model()
    user = User.objects.create_user(username="staff2", password="pass", is_staff=True)
    client.force_login(user)

    monkeypatch.setenv("MINIMEGA_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("MINIMEGA_ALLOW_KILL", "1")

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="killed", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    response = client.post(
        reverse("dashboard:digital_twin_kill"),
        data=json.dumps({"confirm": "KILL_MINIMEGA"}),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "killed"
