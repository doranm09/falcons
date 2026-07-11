from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET

from django.conf import settings


def _repo_root() -> Path | None:
    raw = str(getattr(settings, "ICS_RISK_ASSESSMENT_REPO_PATH", "") or "").strip()
    if not raw:
        return None
    return Path(raw).expanduser()


def _repo_path(*parts: str) -> Path | None:
    root = _repo_root()
    if root is None:
        return None
    return root.joinpath(*parts)


def _repo_model_paths() -> dict[str, Path | None]:
    return {
        "upload": _repo_path("upload", "sim_system.json"),
        "db": _repo_path("db", "sim_system.json"),
    }


def _preferred_model_path() -> tuple[str, Path | None]:
    for source, path in _repo_model_paths().items():
        if path is not None and path.exists():
            return source, path
    return "", _repo_model_paths()["upload"]


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return payload


def _safe_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    return _read_json(path)


def _local_tag(element: ET.Element) -> str:
    return str(element.tag or "").split("}", 1)[-1].strip().lower()


def _child_texts(element: ET.Element, tag_name: str) -> list[str]:
    values: list[str] = []
    wanted = tag_name.lower()
    for child in list(element):
        if _local_tag(child) != wanted:
            continue
        text = "".join(child.itertext()).strip()
        if text:
            values.append(text)
    return values


def _first_child_text(element: ET.Element, tag_name: str) -> str:
    values = _child_texts(element, tag_name)
    return values[0] if values else ""


def _system_node_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    nodes_obj = payload.get("nodes")
    if isinstance(nodes_obj, dict):
        for node_id, record in nodes_obj.items():
            if isinstance(record, dict):
                entries.append({"id": str(node_id), "section": "nodes", "record": record})
        return entries

    for section_name, section_payload in payload.items():
        if section_name in {"version", "metadata"}:
            continue
        if not isinstance(section_payload, dict):
            continue
        for node_id, record in section_payload.items():
            if isinstance(record, dict):
                entries.append({"id": str(node_id), "section": str(section_name), "record": record})
    return entries


def _system_graph(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entries = _system_node_entries(payload)
    nodes = [
        {
            "id": entry["id"],
            "label": entry["id"],
            "type": str(entry["record"].get("type") or "Unknown"),
            "section": entry["section"],
        }
        for entry in entries
    ]
    node_by_id = {node["id"]: node for node in nodes}
    normalized_networks: dict[str, str] = {}
    for entry in entries:
        section = str(entry["section"]).strip().lower()
        node_type = str(entry["record"].get("type") or "").strip().lower()
        if "net" in section or "network" in node_type:
            key = entry["id"].strip().lower()
            if key and key not in normalized_networks:
                normalized_networks[key] = entry["id"]

    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, section: str) -> None:
        if node_id in node_by_id:
            return
        node = {"id": node_id, "label": label, "type": node_type, "section": section}
        nodes.append(node)
        node_by_id[node_id] = node

    def add_edge(source: str, target: str) -> None:
        if source not in node_by_id or target not in node_by_id:
            return
        edge_id = f"{source}::{target}"
        if edge_id in seen:
            return
        seen.add(edge_id)
        edges.append({"id": edge_id, "source": source, "target": target})

    for entry in entries:
        if str(entry["section"]).strip().lower() != "digital":
            continue
        networks = entry["record"].get("networks")
        if not isinstance(networks, dict):
            continue
        for network_name in networks.keys():
            clean_name = str(network_name).strip()
            if not clean_name:
                continue
            key = clean_name.lower()
            network_id = normalized_networks.get(key)
            if not network_id:
                network_id = f"network:{key}"
                add_node(network_id, clean_name, "Network", "network")
            add_edge(entry["id"], network_id)

    for entry in entries:
        source_map = entry["record"].get("source")
        if isinstance(source_map, dict):
            for source_id in source_map.keys():
                add_edge(str(source_id), entry["id"])
        target_map = entry["record"].get("target")
        if isinstance(target_map, dict):
            for target_id in target_map.keys():
                add_edge(entry["id"], str(target_id))

    return nodes, edges


def _count_fault_trees(root: Path | None) -> int:
    if root is None:
        return 0
    fts_root = root / "outputs" / "fts"
    if not fts_root.exists():
        return 0
    return sum(1 for _ in fts_root.rglob("value.json"))


def _parse_bif(path: Path) -> dict[str, Any]:
    tree = ET.parse(path)
    root = tree.getroot()
    network = None
    for element in root.iter():
        if _local_tag(element) == "network":
            network = element
            break
    if network is None:
        raise ValueError(f"Could not find NETWORK element in {path}.")

    outcomes: dict[str, list[str]] = {}
    definitions: dict[str, dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()

    for child in list(network):
        tag = _local_tag(child)
        if tag == "variable":
            node_id = _first_child_text(child, "name")
            if not node_id:
                continue
            node_outcomes = _child_texts(child, "outcome")
            outcomes[node_id] = node_outcomes
            nodes.append(
                {
                    "id": node_id,
                    "label": node_id,
                    "type": "BN Variable",
                    "section": "bayesian",
                }
            )
        elif tag == "definition":
            target = _first_child_text(child, "for")
            if not target:
                continue
            parents = _child_texts(child, "given")
            table_text = _first_child_text(child, "table")
            table = []
            for item in table_text.split():
                try:
                    table.append(float(item))
                except ValueError:
                    continue
            definitions[target] = {"givens": parents, "table": table}
            for source in parents:
                edge_id = f"{source}::{target}"
                if edge_id in seen_edges:
                    continue
                seen_edges.add(edge_id)
                edges.append({"id": edge_id, "source": source, "target": target})

    return {
        "nodes": nodes,
        "edges": edges,
        "outcomes": outcomes,
        "definitions": definitions,
    }


def _load_cpt_nodes(root: Path | None) -> dict[str, Any]:
    cpt_path = root / "outputs" / "dbn_2_with_cpt.json" if root else None
    payload = _safe_json(cpt_path)
    nodes = payload.get("nodes") if isinstance(payload, dict) else None
    return nodes if isinstance(nodes, dict) else {}


def _dashboard_color(node_type: str) -> str:
    key = str(node_type or "").strip().lower().replace(" ", "_")
    palette = {
        "computer": "#2563eb",
        "plc": "#16a34a",
        "firewall": "#e11d48",
        "network": "#ea580c",
        "valve": "#7c3aed",
        "valve_ctrl": "#6366f1",
        "pressure": "#0284c7",
        "pressurizer": "#0d9488",
        "junction": "#65a30d",
        "heater_ctrl": "#f59e0b",
        "tr_press": "#0891b2",
        "digital": "#475569",
        "physical": "#92400e",
        "flow": "#15803d",
        "function": "#ca8a04",
        "bn_variable": "#94a3b8",
    }
    if key in palette:
        return palette[key]
    hue = 0
    for char in key:
        hue = (hue * 31 + ord(char)) % 360
    return f"hsl({hue} 52% 46%)"


def _enumerate_parent_assignments(parents: list[str], outcomes: dict[str, list[str]]) -> list[list[str]]:
    if not parents:
        return [[]]
    head, *tail = parents
    tail_assignments = _enumerate_parent_assignments(tail, outcomes)
    assignments: list[list[str]] = []
    for state in outcomes.get(head, []):
        for tail_assignment in tail_assignments:
            assignments.append([state, *tail_assignment])
    return assignments


def _build_bif_rows(
    parents: list[str],
    outcomes: dict[str, list[str]],
    child_outcomes: list[str],
    values: list[float],
) -> list[dict[str, Any]]:
    outcome_count = len(child_outcomes)
    if outcome_count == 0:
        return []
    if not parents:
        probabilities = values[:outcome_count]
        if len(probabilities) < outcome_count:
            return []
        return [{"parent_assignment": [], "probabilities": probabilities}]

    rows: list[dict[str, Any]] = []
    index = 0
    for assignment in _enumerate_parent_assignments(parents, outcomes):
        probabilities = values[index:index + outcome_count]
        if len(probabilities) < outcome_count:
            break
        rows.append({"parent_assignment": assignment, "probabilities": probabilities})
        index += outcome_count
    return rows


def _nominal_mismatch(bif_cpt: dict[str, Any]) -> bool:
    if not bif_cpt.get("found"):
        return False
    outcomes = bif_cpt.get("outcomes") or []
    rows = bif_cpt.get("rows") or []
    nominal_index = next(
        (index for index, outcome in enumerate(outcomes) if str(outcome).strip().lower() == "nominal"),
        None,
    )
    if nominal_index is None:
        return False
    for row in rows:
        probabilities = row.get("probabilities") or []
        if nominal_index >= len(probabilities):
            continue
        try:
            nominal_probability = float(probabilities[nominal_index])
        except (TypeError, ValueError):
            continue
        if abs(nominal_probability - 1.0) > 1e-5:
            continue
        parent_assignment = row.get("parent_assignment") or []
        if any(str(state).strip().lower() not in {"", "nominal", "normal", "—"} for state in parent_assignment):
            return True
    return False


def _bif_cpt_payload(parsed_bif: dict[str, Any], node_id: str) -> dict[str, Any]:
    outcomes = parsed_bif.get("outcomes") or {}
    definitions = parsed_bif.get("definitions") or {}
    child_outcomes = outcomes.get(node_id)
    definition = definitions.get(node_id)
    if not isinstance(child_outcomes, list) or not isinstance(definition, dict):
        return {"found": False}
    parents = [
        str(parent)
        for parent in (definition.get("givens") or [])
        if str(parent).strip()
    ]
    table = [
        float(value)
        for value in (definition.get("table") or [])
        if isinstance(value, (int, float))
    ]
    rows = _build_bif_rows(parents, outcomes, child_outcomes, table)
    combo_count = len(_enumerate_parent_assignments(parents, outcomes)) if parents else 1
    return {
        "found": True,
        "outcomes": child_outcomes,
        "parents": parents,
        "rows": rows,
        "expected_entries": combo_count * len(child_outcomes),
        "actual_entries": len(table),
    }


def _fts_condition_folders(root: Path | None, node_id: str) -> list[str]:
    if root is None:
        return []
    node_root = root / "outputs" / "fts" / node_id
    if not node_root.exists():
        return []
    folders = []
    for child in sorted(node_root.iterdir(), key=lambda item: item.name.lower()):
        if child.is_dir() and (child / "value.json").exists():
            folders.append(child.name)
    return folders


def _fts_root(root: Path | None) -> Path | None:
    if root is None:
        return None
    return root / "outputs" / "fts"


def _fault_tree_component_dirs(root: Path | None) -> list[Path]:
    fts_root = _fts_root(root)
    if fts_root is None or not fts_root.exists():
        return []
    component_dirs = []
    for child in sorted(fts_root.iterdir(), key=lambda item: item.name.lower()):
        if child.is_dir() and (child / "component.json").exists():
            component_dirs.append(child)
    return component_dirs


def _fault_tree_condition_dirs(component_dir: Path) -> list[Path]:
    condition_dirs = []
    for child in sorted(component_dir.iterdir(), key=lambda item: item.name.lower()):
        if child.is_dir() and ((child / "rule.json").exists() or (child / "value.json").exists()):
            condition_dirs.append(child)
    return condition_dirs


def _fault_tree_component_summary(component_dir: Path) -> dict[str, Any]:
    component = _safe_json(component_dir / "component.json") or {}
    states = component.get("states") if isinstance(component.get("states"), list) else []
    fault_count = len(component.get("faults") or {}) if isinstance(component.get("faults"), dict) else 0
    vulnerability_count = sum(
        len(value)
        for key, value in component.items()
        if str(key).startswith("vul_") and isinstance(value, dict)
    )
    defense_count = sum(
        len(value)
        for key, value in component.items()
        if str(key).startswith("defense") and isinstance(value, dict)
    )
    condition_dirs = _fault_tree_condition_dirs(component_dir)
    return {
        "id": component_dir.name,
        "path": _display_path(component_dir),
        "states": states,
        "fault_count": fault_count,
        "vulnerability_count": vulnerability_count,
        "defense_count": defense_count,
        "condition_count": len(condition_dirs),
        "condition_folders": [item.name for item in condition_dirs],
    }


def _fault_tree_condition_detail(condition_dir: Path) -> dict[str, Any]:
    rule = _safe_json(condition_dir / "rule.json") or {}
    value = _safe_json(condition_dir / "value.json") or {}
    inputs = {}
    if isinstance(rule.get("inputs"), dict):
        inputs = rule.get("inputs") or {}
    elif isinstance(value.get("inputs"), dict):
        inputs = value.get("inputs") or {}
    events = rule.get("events") if isinstance(rule.get("events"), list) else []
    value_rules = rule.get("value_rules") if isinstance(rule.get("value_rules"), dict) else {}
    raw_values = value.get("values") if isinstance(value.get("values"), list) else []
    graph_variants: list[dict[str, Any]] = []
    graph_default_state = ""
    graph_scenario = ""
    sample_rows = []
    for row in raw_values[:5]:
        if not isinstance(row, dict) or not row:
            continue
        label, payload = next(iter(row.items()))
        payload_dict = payload if isinstance(payload, dict) else {}
        events_map = payload_dict.get("events") if isinstance(payload_dict.get("events"), dict) else {}
        probabilities = payload_dict.get("probabilities") if isinstance(payload_dict.get("probabilities"), dict) else {}
        sample_rows.append(
            {
                "label": str(label),
                "event_count": len(events_map),
                "probabilities": probabilities,
            }
        )

    first_payload: dict[str, Any] = {}
    for row in raw_values:
        if not isinstance(row, dict) or not row:
            continue
        label, payload = next(iter(row.items()))
        graph_scenario = str(label)
        first_payload = payload if isinstance(payload, dict) else {}
        break

    effective_value_rules = value_rules
    if not effective_value_rules:
        scenario_value_rules = first_payload.get("value_rules")
        if isinstance(scenario_value_rules, dict):
            effective_value_rules = scenario_value_rules
    effective_events = first_payload.get("events") if isinstance(first_payload.get("events"), dict) else {}
    graph_states = _fault_tree_graph_outcome_keys(first_payload, effective_value_rules if isinstance(effective_value_rules, dict) else {})
    graph_default_state = _fault_tree_default_state(graph_states)
    if graph_states:
        for state_name in graph_states:
            graph_variants.append(
                {
                    "state": state_name,
                    "scenario": graph_scenario or "_",
                    "graph": _fault_tree_build_state_graph(
                        condition_name=condition_dir.name,
                        state=state_name,
                        value_rules=effective_value_rules if isinstance(effective_value_rules, dict) else {},
                        fault_probabilities=effective_events if isinstance(effective_events, dict) else {},
                        scenario_label=graph_scenario or "_",
                    ),
                }
            )

    return {
        "name": condition_dir.name,
        "path": _display_path(condition_dir),
        "rule_path": _display_path(condition_dir / "rule.json"),
        "value_path": _display_path(condition_dir / "value.json"),
        "inputs": inputs,
        "events": events,
        "event_count": len(events),
        "state_rules": list(value_rules.keys()),
        "value_rules": value_rules,
        "sample_count": len(raw_values),
        "sample_rows": sample_rows,
        "rule": rule,
        "graph_default_state": graph_default_state,
        "graph_scenario": graph_scenario or "_",
        "graphs": graph_variants,
        "value_preview": {
            "inputs": value.get("inputs") if isinstance(value.get("inputs"), dict) else inputs,
            "values": raw_values[:5],
        },
    }


def _display_path(path: Path | None) -> str:
    return str(path) if path is not None else ""


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or ""))
    text = re.sub(r"_+", "_", text).strip("_")
    return text[:120] or "item"


def _fault_tree_normalize_children(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _fault_tree_is_gate_type(node_type: str) -> bool:
    return str(node_type or "") in {"and_gate", "or_gate", "not_gate", "kofn_gate"}


def _fault_tree_layout_footprint(node_type: str) -> tuple[int, int]:
    kind = str(node_type or "")
    if kind == "basic_event":
        return (88, 88)
    if kind in {"top_event", "intermediate_event"}:
        return (96, 56)
    if kind in {"and_gate", "or_gate"}:
        return (44, 44)
    if kind == "not_gate":
        return (31, 31)
    if kind == "kofn_gate":
        return (62, 62)
    return (96, 56)


def _layout_fault_tree_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    node_by_id = {str(node.get("id") or ""): node for node in nodes if str(node.get("id") or "")}
    children: dict[str, list[str]] = {}
    for edge in edges:
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if not source or not target:
            continue
        children.setdefault(target, []).append(source)

    top_node = next((node for node in nodes if str(node.get("type") or "") == "top_event"), None)
    if top_node is None:
        return

    max_width = 0
    max_height = 0
    for node in nodes:
        width, height = _fault_tree_layout_footprint(str(node.get("type") or ""))
        max_width = max(max_width, width)
        max_height = max(max_height, height)

    layout_min_node_gap = 24
    gate_upward_shift = 18
    y_step = max(104, int(max_height + 12 + layout_min_node_gap))
    x_step = max(88, int(max_width + layout_min_node_gap * 2))
    margin_x = 48
    margin_y = 48

    leaf_sequence = {"value": 0}

    def place(node_id: str, depth: int) -> float:
        node = node_by_id.get(node_id)
        if node is None:
            return 0.0
        child_ids = children.get(node_id, [])
        node["y"] = margin_y + depth * y_step
        if _fault_tree_is_gate_type(str(node.get("type") or "")) and depth > 0:
            node["y"] = float(node["y"]) - gate_upward_shift
        if not child_ids:
            node["x"] = margin_x + leaf_sequence["value"] * x_step
            leaf_sequence["value"] += 1
            return float(node["x"])
        child_positions = [place(child_id, depth + 1) for child_id in child_ids]
        node["x"] = sum(child_positions) / max(len(child_positions), 1)
        return float(node["x"])

    top_id = str(top_node.get("id") or "")
    place(top_id, 0)

    depth_by_id: dict[str, int] = {top_id: 0}
    queue = [top_id]
    while queue:
        current = queue.pop(0)
        current_depth = depth_by_id.get(current, 0)
        for child_id in children.get(current, []):
            depth_by_id[child_id] = current_depth + 1
            queue.append(child_id)

    def spread_by_depth() -> None:
        rows: dict[int, list[dict[str, Any]]] = {}
        for node in nodes:
            node_id = str(node.get("id") or "")
            depth = depth_by_id.get(node_id)
            if depth is None:
                continue
            rows.setdefault(depth, []).append(node)
        for row in rows.values():
            row.sort(key=lambda item: float(item.get("x") or 0))
            cursor = float(margin_x)
            for node in row:
                width, _ = _fault_tree_layout_footprint(str(node.get("type") or ""))
                half = width / 2
                minimum_center = cursor + half
                if float(node.get("x") or 0) < minimum_center:
                    node["x"] = minimum_center
                cursor = float(node.get("x") or 0) + half + layout_min_node_gap

    def recenter_parents() -> None:
        ordered: list[str] = []

        def post_order(node_id: str) -> None:
            for child_id in children.get(node_id, []):
                post_order(child_id)
            ordered.append(node_id)

        post_order(top_id)
        for node_id in ordered:
            child_ids = children.get(node_id, [])
            if not child_ids:
                continue
            node = node_by_id.get(node_id)
            if node is None:
                continue
            child_positions = [float(node_by_id[child_id].get("x") or 0) for child_id in child_ids if child_id in node_by_id]
            if child_positions:
                node["x"] = sum(child_positions) / len(child_positions)

    for _ in range(8):
        spread_by_depth()
        recenter_parents()


def _fault_tree_graph_outcome_keys(spec: dict[str, Any], value_rules: dict[str, Any]) -> list[str]:
    if value_rules:
        return [str(key) for key in value_rules.keys()]
    raw_value_rules = spec.get("value_rules")
    if isinstance(raw_value_rules, dict) and raw_value_rules:
        return [str(key) for key in raw_value_rules.keys()]
    probabilities = spec.get("probabilities")
    if isinstance(probabilities, dict) and probabilities:
        return [str(key) for key in probabilities.keys()]
    return []


def _fault_tree_default_state(states: list[str]) -> str:
    preferences = ("abnormal", "compromised", "fault", "failed", "degraded", "unsafe")
    lowered = {str(state).lower(): str(state) for state in states}
    for wanted in preferences:
        if wanted in lowered:
            return lowered[wanted]
    return states[0] if states else ""


def _fault_tree_build_state_graph(
    condition_name: str,
    state: str,
    value_rules: dict[str, Any],
    fault_probabilities: dict[str, Any],
    scenario_label: str,
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    basic_event_by_label: dict[str, str] = {}
    value_rule_node_by_name: dict[str, str] = {}
    counter = {"value": 0}
    prefix = _slug(f"{condition_name}__{scenario_label}__{state}")

    def mk(suffix: str) -> str:
        counter["value"] += 1
        return f"{prefix}__{suffix}__{counter['value']}"

    def add_node(node_id: str, label: str, node_type: str, probability: float | None = None, description: str = "") -> None:
        node: dict[str, Any] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "x": 0,
            "y": 0,
            "description": description,
        }
        if probability is not None:
            node["probability"] = probability
        nodes.append(node)

    def add_edge(source: str, target: str) -> None:
        edges.append({"id": mk("e"), "source": source, "target": target})

    def build_expr(expr: Any) -> str:
        if isinstance(expr, str):
            if expr in value_rule_node_by_name:
                return value_rule_node_by_name[expr]
            if expr in value_rules:
                ref_id = build_expr(value_rules[expr])
                value_rule_node_by_name[expr] = ref_id
                return ref_id
            if expr in basic_event_by_label:
                return basic_event_by_label[expr]
            probability_value = fault_probabilities.get(expr)
            probability = None
            if isinstance(probability_value, (int, float)):
                probability = float(probability_value)
                if not (0 <= probability <= 1):
                    probability = 0.01
            else:
                probability = 0.01
            node_id = mk(f"be-{_slug(expr)}")
            add_node(node_id, expr, "basic_event", probability=probability)
            basic_event_by_label[expr] = node_id
            return node_id

        if isinstance(expr, dict):
            keys = [key for key in ("OR", "AND", "NOT") if key in expr]
            if not keys:
                raise ValueError(f"Invalid gate object (no OR/AND/NOT): {json.dumps(expr)[:80]}")
            if len(keys) == 1:
                return build_gate(keys[0], expr[keys[0]])
            gate_id = mk("implicit-and")
            add_node(gate_id, "AND", "and_gate", description="implicit (multi-key)")
            for key in keys:
                child_id = build_gate(key, expr[key])
                add_edge(child_id, gate_id)
            return gate_id

        raise ValueError(f"Unsupported expression type: {type(expr).__name__}")

    def build_gate(kind: str, value: Any) -> str:
        if kind == "NOT":
            gate_id = mk("not")
            add_node(gate_id, "NOT", "not_gate")
            child_id = build_expr(value)
            add_edge(child_id, gate_id)
            return gate_id

        child_values = _fault_tree_normalize_children(value)
        gate_id = mk(kind.lower())
        gate_type = "or_gate" if kind == "OR" else "and_gate"
        add_node(gate_id, kind, gate_type)
        for child_value in child_values:
            child_id = build_expr(child_value)
            add_edge(child_id, gate_id)
        return gate_id

    root_expr = value_rules.get(state)
    if root_expr is None:
        event_names = [str(key).strip() for key in fault_probabilities.keys() if str(key).strip()]
        if not event_names:
            root_id = mk("be-empty")
            add_node(root_id, "NoEvents", "basic_event", probability=0.0, description="Fallback event: value_rules missing and events empty")
        elif len(event_names) == 1:
            root_id = build_expr(event_names[0])
        else:
            root_id = build_expr({"OR": event_names})
    else:
        root_id = build_expr(root_expr)

    top_id = f"{prefix}__top"
    add_node(top_id, state, "top_event")
    add_edge(root_id, top_id)

    normalized_edges: list[dict[str, Any]] = []
    for edge in edges:
        source_node = next((node for node in nodes if node["id"] == edge["source"]), None)
        target_node = next((node for node in nodes if node["id"] == edge["target"]), None)
        if source_node and target_node and _fault_tree_is_gate_type(str(source_node.get("type") or "")) and _fault_tree_is_gate_type(str(target_node.get("type") or "")):
            intermediate_id = mk("ie")
            add_node(intermediate_id, "Intermediate", "intermediate_event")
            normalized_edges.append({"id": mk("e"), "source": edge["source"], "target": intermediate_id})
            normalized_edges.append({"id": mk("e"), "source": intermediate_id, "target": edge["target"]})
            continue
        normalized_edges.append(edge)
    edges[:] = normalized_edges

    _layout_fault_tree_graph(nodes, edges)
    return {"nodes": nodes, "edges": edges}


def risk_repo_summary() -> dict[str, Any]:
    root = _repo_root()
    model_source, model_path = _preferred_model_path()
    model_paths = _repo_model_paths()
    upload_path = model_paths["upload"]
    bif_path = _repo_path("outputs", "dbn.bifxml")
    cpt_path = _repo_path("outputs", "dbn_2_with_cpt.json")
    pipeline_path = _repo_path("outputs", "pipeline_log.json")

    payload = _safe_json(model_path)
    nodes, edges = _system_graph(payload) if payload else ([], [])

    return {
        "repo_available": bool(root and root.exists()),
        "repo_path": _display_path(root),
        "upload_path": _display_path(upload_path),
        "db_model_path": _display_path(model_paths["db"]),
        "model_path": _display_path(model_path),
        "model_source": model_source,
        "sim_system_found": bool(model_path and model_path.exists()),
        "bayesian_path": _display_path(bif_path),
        "bayesian_found": bool(bif_path and bif_path.exists()),
        "cpt_path": _display_path(cpt_path),
        "cpt_found": bool(cpt_path and cpt_path.exists()),
        "pipeline_log_path": _display_path(pipeline_path),
        "pipeline_log_found": bool(pipeline_path and pipeline_path.exists()),
        "fault_tree_count": _count_fault_trees(root),
        "metrics": {
            "nodes": len(nodes),
            "links": len(edges),
        },
    }


def risk_repo_system_graph() -> dict[str, Any]:
    model_source, model_path = _preferred_model_path()
    payload = _safe_json(model_path)
    if payload is None:
        return {
            "found": False,
            "path": _display_path(model_path),
            "source": model_source,
            "nodes": [],
            "edges": [],
        }
    nodes, edges = _system_graph(payload)
    return {
        "found": True,
        "path": _display_path(model_path),
        "source": model_source,
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "nodes": len(nodes),
            "edges": len(edges),
        },
    }


def risk_repo_model_payload() -> dict[str, Any]:
    model_source, model_path = _preferred_model_path()
    payload = _safe_json(model_path)
    return {
        "found": payload is not None,
        "path": _display_path(model_path),
        "source": model_source,
        "data": payload,
    }


def risk_repo_bayesian_graph() -> dict[str, Any]:
    root = _repo_root()
    bif_path = _repo_path("outputs", "dbn.bifxml")
    if bif_path is None or not bif_path.exists():
        return {
            "found": False,
            "path": _display_path(bif_path),
            "nodes": [],
            "edges": [],
            "cpt_path": _display_path(_repo_path("outputs", "dbn_2_with_cpt.json")),
            "cpt_found": False,
        }

    parsed_bif = _parse_bif(bif_path)
    cpt_nodes = _load_cpt_nodes(root)
    nodes = []
    for node in parsed_bif["nodes"]:
        node_id = node["id"]
        cpt_node = cpt_nodes.get(node_id)
        node_type = str(cpt_node.get("type") if isinstance(cpt_node, dict) else node.get("type") or "BN Variable")
        section = str(cpt_node.get("category") if isinstance(cpt_node, dict) else node.get("section") or "bayesian")
        bif_cpt = _bif_cpt_payload(parsed_bif, node_id)
        nodes.append(
            {
                "id": node_id,
                "label": node["label"],
                "type": node_type,
                "section": section,
                "color": _dashboard_color(node_type),
                "cpt_nominal_mismatch": _nominal_mismatch(bif_cpt),
            }
        )

    return {
        "found": True,
        "path": _display_path(bif_path),
        "nodes": nodes,
        "edges": parsed_bif["edges"],
        "cpt_path": _display_path(_repo_path("outputs", "dbn_2_with_cpt.json")),
        "cpt_found": bool(cpt_nodes),
    }


def risk_repo_bayesian_node_detail(node_id: str) -> dict[str, Any]:
    root = _repo_root()
    bif_path = _repo_path("outputs", "dbn.bifxml")
    parsed_bif = _parse_bif(bif_path) if bif_path and bif_path.exists() else {"outcomes": {}, "definitions": {}}
    cpt_nodes = _load_cpt_nodes(root)
    detail = cpt_nodes.get(node_id)
    bif_cpt = _bif_cpt_payload(parsed_bif, node_id)
    return {
        "found": detail is not None or bif_cpt.get("found", False),
        "id": node_id,
        "detail": detail,
        "bif_cpt": bif_cpt,
        "fts_condition_folders": _fts_condition_folders(root, node_id),
    }


def risk_repo_pipeline_log() -> dict[str, Any]:
    pipeline_path = _repo_path("outputs", "pipeline_log.json")
    payload = _safe_json(pipeline_path)
    return {
        "found": payload is not None,
        "path": _display_path(pipeline_path),
        "data": payload,
    }


def risk_repo_fault_tree_summary() -> dict[str, Any]:
    root = _repo_root()
    fts_root = _fts_root(root)
    items = [_fault_tree_component_summary(component_dir) for component_dir in _fault_tree_component_dirs(root)]
    total_conditions = sum(int(item.get("condition_count") or 0) for item in items)
    return {
        "found": bool(items),
        "path": _display_path(fts_root),
        "component_count": len(items),
        "condition_count": total_conditions,
        "items": items,
    }


def risk_repo_fault_tree_detail(node_id: str) -> dict[str, Any]:
    root = _repo_root()
    component_dir = (_fts_root(root) / node_id) if _fts_root(root) is not None else None
    if component_dir is None or not component_dir.exists() or not component_dir.is_dir():
        return {
            "found": False,
            "id": node_id,
            "path": _display_path(component_dir),
            "component": {},
            "conditions": [],
        }

    component = _safe_json(component_dir / "component.json") or {}
    conditions = [_fault_tree_condition_detail(condition_dir) for condition_dir in _fault_tree_condition_dirs(component_dir)]
    return {
        "found": True,
        "id": node_id,
        "path": _display_path(component_dir),
        "component": component,
        "conditions": conditions,
    }
