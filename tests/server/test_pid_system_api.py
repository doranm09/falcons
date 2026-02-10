from django.test import override_settings
from django.urls import reverse


@override_settings(RISK_ASSESSMENT_SIM_SYSTEM_PATH="docs/examples/sim_system_example.json")
def test_pid_system_api_target(client):
    response = client.get(
        reverse("dashboard:risk_assessment_pid_system_api"),
        {"source": "target", "include_network": "0"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "elements" in data
    assert "meta" in data
    assert data["meta"]["variables"] == 3
    assert data["meta"]["connections"] == 2
