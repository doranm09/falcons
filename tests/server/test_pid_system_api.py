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


@override_settings(RISK_ASSESSMENT_SIM_SYSTEM_PATH="")
def test_pid_system_api_auto_falls_back_to_latest_generated_model(client, settings, tmp_path):
    output_dir = tmp_path / "pid_drawio"
    output_dir.mkdir()
    (output_dir / "20240210_sim_system.json").write_text(
        """
        {
          "variables": {
            "PLC-1": {
              "type": "controller",
              "domain": "cyber",
              "ip": "10.0.0.10"
            }
          },
          "connections": []
        }
        """.strip(),
        encoding="utf-8",
    )
    settings.PID_DRAWIO_OUTPUT_DIR = str(output_dir)

    response = client.get(
        reverse("dashboard:risk_assessment_pid_system_api"),
        {"source": "auto", "include_network": "0"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["meta"]["variables"] == 1
    assert data["meta"]["source"] == "latest"
