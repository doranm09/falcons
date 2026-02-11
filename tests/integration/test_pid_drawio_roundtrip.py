from pathlib import Path

from knowledge_extraction.drawio import (
    generate_drawio_from_sim_system,
    load_sim_system,
    parse_drawio_sim_system,
)


def test_drawio_roundtrip(tmp_path: Path):
    sim_system = load_sim_system("docs/examples/sim_system_example.json")
    xml = generate_drawio_from_sim_system(sim_system, diagram_name="Roundtrip")

    xml_path = tmp_path / "roundtrip.xml"
    xml_path.write_text(xml, encoding="utf-8")

    parsed = parse_drawio_sim_system(xml_path)

    assert set(parsed["variables"].keys()) == set(sim_system["variables"].keys())
    assert len(parsed["connections"]) == len(sim_system["connections"])
