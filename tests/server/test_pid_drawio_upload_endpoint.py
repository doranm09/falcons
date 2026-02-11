from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
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


@override_settings(PID_DRAWIO_OUTPUT_DIR=None)
def test_pid_drawio_upload_endpoint(client, tmp_path: Path, settings):
    settings.PID_DRAWIO_OUTPUT_DIR = str(tmp_path)
    upload = SimpleUploadedFile("diagram.xml", DRAWIO_XML.encode("utf-8"), content_type="text/xml")

    response = client.post(
        reverse("dashboard:risk_assessment_pid_upload"),
        {"drawio_file": upload},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["variables_count"] == 2
    assert data["connections_count"] == 1

    sim_path = Path(data["sim_system_path"])
    assert sim_path.exists()

    xml_path = Path(data["drawio_path"])
    assert xml_path.exists()
