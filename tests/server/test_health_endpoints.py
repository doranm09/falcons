import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_healthz_endpoint(client):
    resp = client.get(reverse("dashboard:healthz"))
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert "status" in body
    assert "checks" in body


@pytest.mark.django_db
def test_metrics_endpoint(client):
    resp = client.get(reverse("dashboard:metrics"))
    assert resp.status_code == 200
    assert b"cybertwin_service_up" in resp.content
