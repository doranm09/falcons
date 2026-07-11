import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_siem_event_explorer_page_renders(client):
    resp = client.get(reverse("dashboard:siem_event_explorer"))
    assert resp.status_code == 200
    content = resp.content.decode("utf-8")
    assert "SIEM Event Explorer" in content
    assert "data-testid=\"siem-events-table\"" in content
    assert "id=\"siem-source-ip\"" in content
    assert "id=\"siem-source-port\"" in content
    assert "id=\"siem-destination-ip\"" in content
    assert "id=\"siem-destination-port\"" in content
    assert "id=\"siem-community-id\"" in content
    assert "data-workflow=\"modbus\"" in content
    assert "Sensor stats noise is hidden by default." in content
