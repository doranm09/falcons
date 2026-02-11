from dashboard.pid_drawio import safe_filename


def test_safe_filename_sanitizes_and_preserves_extension():
    name = "My Diagram (v1).drawio"
    assert safe_filename(name) == "My_Diagram_v1.drawio"


def test_safe_filename_defaults_extension():
    assert safe_filename("diagram") == "diagram.xml"
