import json
from pathlib import Path

from django.urls import reverse


def test_pid_system_latest_flow(client, tmp_path: Path, settings):
    output_dir = tmp_path / "pid_out"
    output_dir.mkdir(parents=True, exist_ok=True)
    sim_path = output_dir / "20240210_sim_system.json"
    sim_path.write_text(
        json.dumps(
            {
                "variables": {
                    "PLC_1": {"type": "PLC", "domain": "cyber", "ip": "10.0.0.2"},
                    "VALVE_1": {"type": "fbValve", "domain": "physical"},
                },
                "connections": [
                    {"source": "PLC_1", "s_attr": "Output", "target": "VALVE_1", "t_attr": "Input"}
                ],
            }
        ),
        encoding="utf-8",
    )

    settings.PID_DRAWIO_OUTPUT_DIR = str(output_dir)
    settings.RISK_ASSESSMENT_SIM_SYSTEM_PATH = ""

    response = client.get(
        reverse("dashboard:risk_assessment_pid_system_api"),
        {"source": "latest", "include_network": "0"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["meta"]["variables"] == 2
    assert data["meta"]["connections"] == 1
