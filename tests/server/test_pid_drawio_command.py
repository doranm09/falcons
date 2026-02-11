import json
from pathlib import Path

from django.core.management import call_command


def test_pid_drawio_command_generates_sim_system(tmp_path: Path):
    input_xml = Path("docs/examples/pid_drawio_example.xml")
    output_json = tmp_path / "sim_system.json"

    call_command("pid_drawio", "--input", str(input_xml), "--output", str(output_json))

    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert "variables" in data
    assert "connections" in data
    assert "PUMP_1" in data["variables"]
