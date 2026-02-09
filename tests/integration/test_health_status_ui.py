import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_event_explorer_shows_service_status(client):
    resp = client.get(reverse("dashboard:siem_event_explorer"))
    assert resp.status_code == 200
    content = resp.content.decode("utf-8")
    assert "Service Status" in content
    assert "Database" in content or "database" in content
