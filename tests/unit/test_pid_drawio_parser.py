from pathlib import Path

from knowledge_extraction.drawio import parse_drawio_sim_system


def test_parse_drawio_to_sim_system(tmp_path: Path):
    xml = """
    <mxfile>
      <diagram name="UnitTest">
        <mxGraphModel>
          <root>
            <mxCell id="0" />
            <mxCell id="1" parent="0" />
            <object id="obj_1" pid="PUMP_A" type="fbPump" module="UnitTest">
              <mxCell id="v1" value="PUMP_A" vertex="1" parent="1">
                <mxGeometry x="0" y="0" width="120" height="60" as="geometry" />
              </mxCell>
            </object>
            <object id="obj_2" pid="VALVE_B" type="fbValve" module="UnitTest">
              <mxCell id="v2" value="VALVE_B" vertex="1" parent="1">
                <mxGeometry x="180" y="0" width="120" height="60" as="geometry" />
              </mxCell>
            </object>
            <object id="edge_1" s_attr="Output" t_attr="Input">
              <mxCell id="e1" edge="1" parent="1" source="v1" target="v2">
                <mxGeometry relative="1" as="geometry" />
              </mxCell>
            </object>
          </root>
        </mxGraphModel>
      </diagram>
    </mxfile>
    """.strip()

    xml_path = tmp_path / "pid.xml"
    xml_path.write_text(xml, encoding="utf-8")

    sim_system = parse_drawio_sim_system(xml_path)

    variables = sim_system.get("variables", {})
    connections = sim_system.get("connections", [])

    assert set(variables.keys()) == {"PUMP_A", "VALVE_B"}
    assert variables["PUMP_A"]["type"] == "fbPump"
    assert variables["VALVE_B"]["type"] == "fbValve"
    assert len(connections) == 1
    assert connections[0]["source"] == "PUMP_A"
    assert connections[0]["target"] == "VALVE_B"
    assert connections[0]["s_attr"] == "Output"
    assert connections[0]["t_attr"] == "Input"
