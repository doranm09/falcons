from __future__ import annotations

import base64
import html
import json
import re
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree as ET


class DrawioParseError(RuntimeError):
    pass


VARIABLES_KEY = "variables"
CONNECTIONS_KEY = "connections"

RESERVED_VAR_KEYS = {"pid", "id", "label", "type", "module", "domain"}
RESERVED_EDGE_KEYS = {"s_attr", "t_attr", "label"}


@dataclass
class DrawioDiagram:
    name: str
    model: ET.Element


def load_sim_system(path: str | Path) -> Dict[str, Any]:
    with open(Path(path), "r", encoding="utf-8") as f:
        data = json.load(f)
    if VARIABLES_KEY not in data or CONNECTIONS_KEY not in data:
        raise ValueError("sim_system.json must contain 'variables' and 'connections'")
    return data


def save_sim_system(path: str | Path, data: Dict[str, Any]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def parse_drawio_sim_system(xml_path: str | Path) -> Dict[str, Any]:
    diagram = _load_drawio_diagram(xml_path)
    variables, cell_map = _parse_vertices(diagram)
    connections = _parse_edges(diagram, cell_map)
    return {
        VARIABLES_KEY: variables,
        CONNECTIONS_KEY: connections,
    }


def generate_drawio_from_sim_system(
    sim_system: Dict[str, Any],
    diagram_name: str = "P&ID",
    layout_columns: int = 4,
    node_width: int = 140,
    node_height: int = 70,
    h_gap: int = 60,
    v_gap: int = 40,
) -> str:
    variables = sim_system.get(VARIABLES_KEY, {})
    connections = sim_system.get(CONNECTIONS_KEY, [])

    # Ensure endpoints referenced by connections exist as nodes.
    for conn in connections:
        if not isinstance(conn, dict):
            continue
        for key in ("source", "target"):
            node_id = conn.get(key)
            if node_id and node_id not in variables:
                variables[node_id] = {
                    "type": "unknown",
                    "module": "synthetic",
                    "domain": "physical",
                }

    mxfile = ET.Element(
        "mxfile",
        {
            "host": "app.diagrams.net",
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "agent": "cyber_pen_test",
            "version": "20.8.16",
            "type": "device",
        },
    )
    diagram = ET.SubElement(mxfile, "diagram", {"name": diagram_name})
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        {
            "dx": "1200",
            "dy": "800",
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "1",
            "pageScale": "1",
            "pageWidth": "1100",
            "pageHeight": "850",
            "math": "0",
            "shadow": "0",
        },
    )
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    cell_id_by_var: Dict[str, str] = {}
    x = 0
    y = 0
    col = 0
    index = 1
    for var_id, info in variables.items():
        cell_id = f"v{index}"
        cell_id_by_var[var_id] = cell_id
        index += 1

        domain = _infer_domain(str(var_id), info if isinstance(info, dict) else {})
        obj_attrs = {
            "id": f"obj_{cell_id}",
            "pid": str(var_id),
            "label": str(var_id),
            "domain": domain,
        }
        if isinstance(info, dict):
            var_type = info.get("type")
            if var_type:
                obj_attrs["type"] = str(var_type)
            module = info.get("module")
            if module:
                obj_attrs["module"] = str(module)
            for k, v in info.items():
                if k in RESERVED_VAR_KEYS or v in (None, ""):
                    continue
                obj_attrs[str(k)] = str(v)

        node_style = _style_for_domain(domain)
        obj = ET.SubElement(root, "object", obj_attrs)
        cell = ET.SubElement(
            obj,
            "mxCell",
            {
                "id": cell_id,
                "value": html.escape(str(var_id)),
                "style": node_style,
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": str(x),
                "y": str(y),
                "width": str(node_width),
                "height": str(node_height),
                "as": "geometry",
            },
        )

        col += 1
        if col >= max(1, layout_columns):
            col = 0
            x = 0
            y += node_height + v_gap
        else:
            x += node_width + h_gap

    edge_index = 1
    for conn in connections:
        if not isinstance(conn, dict):
            continue
        source = conn.get("source")
        target = conn.get("target")
        if source not in cell_id_by_var or target not in cell_id_by_var:
            continue

        s_attr = str(conn.get("s_attr") or "")
        t_attr = str(conn.get("t_attr") or "")
        label = _format_edge_label(s_attr, t_attr)

        obj = ET.SubElement(
            root,
            "object",
            {
                "id": f"edge_{edge_index}",
                "s_attr": s_attr,
                "t_attr": t_attr,
                "label": label,
            },
        )
        edge_index += 1
        edge_cell = ET.SubElement(
            obj,
            "mxCell",
            {
                "id": f"e{edge_index}",
                "value": html.escape(label),
                "style": "endArrow=block;html=1;strokeColor=#64748b;edgeStyle=orthogonalEdgeStyle;rounded=0;",
                "edge": "1",
                "parent": "1",
                "source": cell_id_by_var[source],
                "target": cell_id_by_var[target],
            },
        )
        ET.SubElement(edge_cell, "mxGeometry", {"relative": "1", "as": "geometry"})

    return ET.tostring(mxfile, encoding="utf-8", xml_declaration=True).decode("utf-8")


# Internal helpers


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _load_drawio_diagram(xml_path: str | Path) -> DrawioDiagram:
    try:
        tree = ET.parse(Path(xml_path))
    except ET.ParseError as exc:
        raise DrawioParseError(f"Failed to parse draw.io XML: {exc}") from exc

    root = tree.getroot()
    root_tag = _strip_ns(root.tag)

    if root_tag == "mxGraphModel":
        return DrawioDiagram(name="P&ID", model=root)

    if root_tag == "diagram":
        model = _diagram_to_model(root)
        name = root.attrib.get("name", "P&ID")
        return DrawioDiagram(name=name, model=model)

    if root_tag != "mxfile":
        raise DrawioParseError(f"Unsupported root tag: {root_tag}")

    diagram = None
    for child in root:
        if _strip_ns(child.tag) == "diagram":
            diagram = child
            break
    if diagram is None:
        raise DrawioParseError("No <diagram> element found in draw.io file")

    name = diagram.attrib.get("name", "P&ID")
    model = _diagram_to_model(diagram)
    return DrawioDiagram(name=name, model=model)


def _diagram_to_model(diagram: ET.Element) -> ET.Element:
    for child in diagram:
        if _strip_ns(child.tag) == "mxGraphModel":
            return child

    raw = diagram.text or ""
    raw = raw.strip()
    if not raw:
        raise DrawioParseError("Empty <diagram> element in draw.io file")

    xml_text = _decode_diagram_text(raw)
    try:
        model = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise DrawioParseError(f"Failed to parse diagram XML: {exc}") from exc
    if _strip_ns(model.tag) != "mxGraphModel":
        raise DrawioParseError("Decoded diagram did not contain mxGraphModel")
    return model


def _decode_diagram_text(raw: str) -> str:
    if raw.startswith("<mxGraphModel"):
        return raw

    try:
        payload = base64.b64decode(raw, validate=False)
    except Exception as exc:
        raise DrawioParseError("Diagram payload is neither XML nor base64") from exc

    for wbits in (-15, 15):
        try:
            decompressed = zlib.decompress(payload, wbits)
            return decompressed.decode("utf-8")
        except Exception:
            continue

    raise DrawioParseError("Unable to decode draw.io diagram payload")


def _parse_vertices(diagram: DrawioDiagram) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    root = _find_child(diagram.model, "root")
    if root is None:
        raise DrawioParseError("mxGraphModel missing <root>")

    variables: Dict[str, Dict[str, Any]] = {}
    cell_map: Dict[str, str] = {}

    for element in list(root):
        tag = _strip_ns(element.tag)
        if tag in ("object", "UserObject"):
            cell = _find_child(element, "mxCell")
            if cell is None:
                continue
            if cell.attrib.get("vertex") == "1":
                var_id, info, cell_id = _parse_vertex_object(element, cell, diagram.name)
                if var_id:
                    variables[var_id] = info
                    cell_map[cell_id] = var_id
        elif tag == "mxCell" and element.attrib.get("vertex") == "1":
            var_id, info, cell_id = _parse_vertex_cell(element, diagram.name)
            if var_id:
                variables[var_id] = info
                cell_map[cell_id] = var_id

    return variables, cell_map


def _parse_edges(diagram: DrawioDiagram, cell_map: Dict[str, str]) -> List[Dict[str, Any]]:
    root = _find_child(diagram.model, "root")
    if root is None:
        raise DrawioParseError("mxGraphModel missing <root>")

    connections: List[Dict[str, Any]] = []

    for element in list(root):
        tag = _strip_ns(element.tag)
        if tag in ("object", "UserObject"):
            cell = _find_child(element, "mxCell")
            if cell is None or cell.attrib.get("edge") != "1":
                continue
            conn = _parse_edge(cell, cell_map, element.attrib)
            if conn:
                connections.append(conn)
        elif tag == "mxCell" and element.attrib.get("edge") == "1":
            conn = _parse_edge(element, cell_map, {})
            if conn:
                connections.append(conn)

    return connections


def _parse_vertex_object(element: ET.Element, cell: ET.Element, default_module: str) -> Tuple[str, Dict[str, Any], str]:
    data = dict(element.attrib)
    pid = data.get("pid") or data.get("id") or data.get("label")
    label = data.get("label") or _clean_label(cell.attrib.get("value"))
    var_id = str(pid or label or cell.attrib.get("id", "")).strip()

    info: Dict[str, Any] = {}
    var_type = data.get("type")
    if var_type:
        info["type"] = str(var_type)
    module = data.get("module") or default_module
    if module:
        info["module"] = str(module)

    for key, value in data.items():
        if key in RESERVED_VAR_KEYS or value in (None, ""):
            continue
        info[str(key)] = str(value)

    for key, value in _extract_data_attrs(cell).items():
        if key in RESERVED_VAR_KEYS or value in (None, ""):
            continue
        info[key] = value

    if "type" not in info:
        info["type"] = "unknown"

    return var_id, info, cell.attrib.get("id", "")


def _parse_vertex_cell(cell: ET.Element, default_module: str) -> Tuple[str, Dict[str, Any], str]:
    label = _clean_label(cell.attrib.get("value"))
    var_id = str(label or cell.attrib.get("id", "")).strip()

    info: Dict[str, Any] = {"type": "unknown", "module": default_module}

    for key, value in _extract_data_attrs(cell).items():
        if key in RESERVED_VAR_KEYS or value in (None, ""):
            continue
        info[key] = value

    return var_id, info, cell.attrib.get("id", "")


def _parse_edge(cell: ET.Element, cell_map: Dict[str, str], metadata: Dict[str, str]) -> Optional[Dict[str, Any]]:
    source_cell = cell.attrib.get("source")
    target_cell = cell.attrib.get("target")
    if not source_cell or not target_cell:
        return None

    source = cell_map.get(source_cell)
    target = cell_map.get(target_cell)
    if not source or not target:
        return None

    s_attr = metadata.get("s_attr") or ""
    t_attr = metadata.get("t_attr") or ""

    if not s_attr and not t_attr:
        label = metadata.get("label") or _clean_label(cell.attrib.get("value"))
        s_attr, t_attr = _parse_edge_label(label)

    return {
        "source": source,
        "s_attr": s_attr,
        "target": target,
        "t_attr": t_attr,
    }


def _find_child(element: ET.Element, name: str) -> Optional[ET.Element]:
    for child in list(element):
        if _strip_ns(child.tag) == name:
            return child
    return None


def _clean_label(value: Optional[str]) -> str:
    if not value:
        return ""
    text = html.unescape(value)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def _extract_data_attrs(cell: ET.Element) -> Dict[str, str]:
    extras: Dict[str, str] = {}
    for key, value in cell.attrib.items():
        if key.startswith("data-"):
            extras[key[5:]] = value
    return extras


def _parse_edge_label(label: str) -> Tuple[str, str]:
    if not label:
        return "", ""
    if "->" in label:
        parts = label.split("->", 1)
        return parts[0].strip(), parts[1].strip()
    if ":" in label:
        parts = label.split(":", 1)
        return parts[0].strip(), parts[1].strip()
    return label.strip(), ""


def _format_edge_label(s_attr: str, t_attr: str) -> str:
    if s_attr and t_attr:
        return f"{s_attr}->{t_attr}"
    if s_attr:
        return s_attr
    if t_attr:
        return t_attr
    return ""


def _infer_domain(var_id: str, info: Dict[str, Any]) -> str:
    raw = info.get("domain") or info.get("layer") or info.get("category")
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in ("cyber", "network", "it", "ot"):
            return "cyber"
        if normalized in ("physical", "process", "plant"):
            return "physical"

    haystack = " ".join(
        str(value).lower()
        for value in (var_id, info.get("type"), info.get("module"), info.get("role"), info.get("name"))
        if value
    )
    for hint in ("plc", "hmi", "scada", "rtu", "server", "switch", "router", "firewall", "historian", "workstation"):
        if hint in haystack:
            return "cyber"
    return "physical"


def _style_for_domain(domain: str) -> str:
    if domain == "cyber":
        return "ellipse;whiteSpace=wrap;html=1;fillColor=#7dd3fc;strokeColor=#0284c7;"
    return "rounded=1;whiteSpace=wrap;html=1;fillColor=#cbd5f5;strokeColor=#6366f1;"
