from pathlib import Path
import json

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse


DRAWIO_XML = """
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


def test_pid_drawio_upload_flow(client, tmp_path: Path, settings):
    output_dir = tmp_path / "pid_out"
    target_path = tmp_path / "risk" / "sim_system.json"
    settings.PID_DRAWIO_OUTPUT_DIR = str(output_dir)
    settings.RISK_ASSESSMENT_SIM_SYSTEM_PATH = str(target_path)

    upload = SimpleUploadedFile("diagram.xml", DRAWIO_XML.encode("utf-8"), content_type="text/xml")

    response = client.post(
        reverse("dashboard:risk_assessment_pid_upload"),
        {"drawio_file": upload, "upload_target": "1"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["upload"]["attempted"] is True
    assert data["upload"]["success"] is True
    assert target_path.exists()
    payload = json.loads(target_path.read_text(encoding="utf-8"))
    assert payload["version"] == "1.0"
    assert "physical" in payload
    assert "PUMP_A" in payload["physical"]
