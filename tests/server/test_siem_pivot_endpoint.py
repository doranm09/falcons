import pytest
from django.urls import reverse

from dashboard.models import Node, ScanRun


@pytest.mark.django_db
def test_siem_pivot_endpoint_found(client):
    scan = ScanRun.objects.create(cidr="10.0.0.0/24", status="COMPLETE", scan_type="ping")
    node = Node.objects.create(scan_run=scan, ip_address="10.0.0.7", name="node-c", status="online")

    resp = client.get(reverse("dashboard:siem_pivot_lookup"), {"asset_ip": "10.0.0.7"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["found"] is True
    assert body["node_id"] == node.id
    assert "node_url" in body


@pytest.mark.django_db
def test_siem_pivot_endpoint_not_found(client):
    resp = client.get(reverse("dashboard:siem_pivot_lookup"), {"asset_ip": "10.0.0.99"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["found"] is False
