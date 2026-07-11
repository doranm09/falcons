from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict


SIM_SYSTEM_SECTION_KEYS = ("digital", "physical", "flow", "function")

RISK_SERVICE_PLACEHOLDER_DIGITAL = {
    "process_main_net": {"type": "network", "source": {}, "target": {}},
    "process_backup_net": {"type": "network", "source": {}, "target": {}},
    "control_main_net": {"type": "network", "source": {}, "target": {}},
    "control_backup_net": {"type": "network", "source": {}, "target": {}},
    "supervisory_net": {"type": "network", "source": {}, "target": {}},
    "mgmt_main_net": {"type": "network", "source": {}, "target": {}},
    "mgmt_backup_net": {"type": "network", "source": {}, "target": {}},
    "process_main_firewall": {
        "type": "Firewall",
        "networks": {"control_main_net": {}, "process_main_net": {}},
        "source": {},
        "target": {},
    },
    "process_backup_firewall": {
        "type": "Firewall",
        "networks": {"control_backup_net": {}, "process_backup_net": {}},
        "source": {},
        "target": {},
    },
    "supervisory_firewall": {
        "type": "Firewall",
        "networks": {"control_main_net": {}, "control_backup_net": {}, "supervisory_net": {}},
        "source": {},
        "target": {},
    },
}

CYBER_HINTS = (
    "plc",
    "hmi",
    "scada",
    "rtu",
    "server",
    "switch",
    "router",
    "firewall",
    "historian",
    "workstation",
    "gateway",
    "database",
    "computer",
)

RISK_SERVICE_DIGITAL_TYPE_ALIASES = {
    "plc": "PLC",
    "controller": "PLC",
    "rtu": "PLC",
    "ied": "PLC",
    "dcs": "PLC",
    "firewall": "Firewall",
    "hmi": "HMI",
    "scada": "HMI",
    "computer": "Computer",
    "desktop": "Computer",
    "workstation": "Computer",
    "server": "Computer",
    "host": "Computer",
    "client": "Computer",
    "database": "Database",
    "db": "Database",
    "historian": "DataHistorian",
    "datahistorian": "DataHistorian",
    "data_historian": "DataHistorian",
    "data-historian": "DataHistorian",
    "network": "network",
    "net": "network",
    "tr_press": "tr_press",
    "valve_ctrl": "valve_ctrl",
    "heater_ctrl": "heater_ctrl",
}


def load_sim_system_json(path: str | Path) -> Dict[str, Any]:
    with open(Path(path), "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_sim_system_json(path: str | Path, data: Dict[str, Any]) -> Path:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


def is_legacy_sim_system(data: Dict[str, Any]) -> bool:
    return isinstance(data, dict) and isinstance(data.get("variables"), dict) and isinstance(data.get("connections"), list)


def is_sectioned_sim_system(data: Dict[str, Any]) -> bool:
    return isinstance(data, dict) and any(isinstance(data.get(section), dict) for section in SIM_SYSTEM_SECTION_KEYS)


def load_local_sim_system(path: str | Path) -> Dict[str, Any]:
    payload = load_sim_system_json(path)
    if is_legacy_sim_system(payload):
        return payload
    if is_sectioned_sim_system(payload):
        return sectioned_to_legacy_sim_system(payload)
    raise ValueError(
        "sim_system.json must contain either legacy 'variables'/'connections' keys "
        "or current sectioned 'digital'/'physical'/'flow'/'function' keys."
    )


def legacy_to_sectioned_sim_system(data: Dict[str, Any]) -> Dict[str, Any]:
    if is_sectioned_sim_system(data):
        return copy.deepcopy(data)
    if not is_legacy_sim_system(data):
        raise ValueError("Legacy sim_system payload must contain 'variables' and 'connections'.")

    variables = data.get("variables") or {}
    connections = data.get("connections") or []

    sectioned: Dict[str, Any] = {
        "version": str(data.get("version") or "1.0"),
        "digital": {},
        "physical": {},
        "flow": {},
        "function": {},
    }
    if isinstance(data.get("metadata"), dict):
        sectioned["metadata"] = copy.deepcopy(data["metadata"])

    translated_nodes: Dict[str, Dict[str, Any]] = {}
    node_types: Dict[str, str] = {}

    for node_id, raw_info in variables.items():
        info = dict(raw_info) if isinstance(raw_info, dict) else {}
        section = _legacy_node_section(str(node_id), info)
        record = {
            key: copy.deepcopy(value)
            for key, value in info.items()
            if key not in {"source", "target", "category"}
        }
        record["type"] = str(record.get("type") or "unknown")
        record["source"] = {}
        record["target"] = {}
        sectioned[section][str(node_id)] = record
        translated_nodes[str(node_id)] = record
        node_types[str(node_id)] = record["type"]

    for raw_connection in connections:
        if not isinstance(raw_connection, dict):
            continue
        source_id = str(raw_connection.get("source") or "").strip()
        target_id = str(raw_connection.get("target") or "").strip()
        if not source_id or not target_id:
            continue
        source_node = translated_nodes.get(source_id)
        target_node = translated_nodes.get(target_id)
        if source_node is None or target_node is None:
            continue

        source_relation = _relation_label(raw_connection.get("s_attr"), node_types.get(target_id, "link"))
        target_relation = _relation_label(raw_connection.get("t_attr"), node_types.get(source_id, "link"))
        source_node["target"][target_id] = source_relation
        target_node["source"][source_id] = target_relation

    return sectioned


def build_risk_service_compatible_sim_system(data: Dict[str, Any]) -> Dict[str, Any]:
    sectioned = legacy_to_sectioned_sim_system(data)
    compatible = copy.deepcopy(sectioned)
    signal_ids = _sectioned_node_ids_by_type(compatible, "signal")

    if signal_ids:
        for section in SIM_SYSTEM_SECTION_KEYS:
            section_payload = compatible.get(section)
            if not isinstance(section_payload, dict):
                continue
            for node_id in signal_ids:
                section_payload.pop(node_id, None)

    for section in SIM_SYSTEM_SECTION_KEYS:
        section_payload = compatible.get(section)
        if not isinstance(section_payload, dict):
            continue
        for node_id, record in section_payload.items():
            if not isinstance(record, dict):
                continue

            raw_record = _locate_sectioned_node(sectioned, node_id) or record
            for side in ("source", "target"):
                mapping = record.get(side)
                if isinstance(mapping, dict):
                    record[side] = {key: value for key, value in mapping.items() if key not in signal_ids}

            if section != "digital":
                continue
            _apply_risk_service_digital_compat(node_id, raw_record, record)

    if signal_ids:
        digital = compatible.setdefault("digital", {})
        for node_id, placeholder in RISK_SERVICE_PLACEHOLDER_DIGITAL.items():
            digital.setdefault(node_id, copy.deepcopy(placeholder))
    return compatible


def sectioned_to_legacy_sim_system(data: Dict[str, Any]) -> Dict[str, Any]:
    if is_legacy_sim_system(data):
        return copy.deepcopy(data)
    if not is_sectioned_sim_system(data):
        raise ValueError("Current sim_system payload must contain sectioned node keys.")

    variables: Dict[str, Dict[str, Any]] = {}
    connections_by_edge: Dict[tuple[str, str], Dict[str, Any]] = {}
    known_nodes = set()

    for section in SIM_SYSTEM_SECTION_KEYS:
        section_obj = data.get(section)
        if not isinstance(section_obj, dict):
            continue
        for node_id, raw_info in section_obj.items():
            if not isinstance(raw_info, dict):
                continue
            info = copy.deepcopy(raw_info)
            info.setdefault("type", "unknown")
            info.setdefault("category", section)
            info.setdefault("domain", "cyber" if section == "digital" else "physical")
            variables[str(node_id)] = info
            known_nodes.add(str(node_id))

    for source_id, source_info in variables.items():
        target_map = source_info.get("target")
        if isinstance(target_map, dict):
            for target_id, relation in target_map.items():
                if not isinstance(target_id, str) or target_id not in known_nodes:
                    continue
                edge = connections_by_edge.setdefault(
                    (source_id, target_id),
                    {"source": source_id, "target": target_id, "s_attr": "", "t_attr": ""},
                )
                edge["s_attr"] = _relation_label(relation)

        source_map = source_info.get("source")
        if isinstance(source_map, dict):
            for upstream_id, relation in source_map.items():
                if not isinstance(upstream_id, str) or upstream_id not in known_nodes:
                    continue
                edge = connections_by_edge.setdefault(
                    (upstream_id, source_id),
                    {"source": upstream_id, "target": source_id, "s_attr": "", "t_attr": ""},
                )
                edge["t_attr"] = _relation_label(relation)

    legacy: Dict[str, Any] = {
        "variables": variables,
        "connections": list(connections_by_edge.values()),
    }
    if isinstance(data.get("metadata"), dict):
        legacy["metadata"] = copy.deepcopy(data["metadata"])
    return legacy


def _legacy_node_section(node_id: str, info: Dict[str, Any]) -> str:
    raw = str(info.get("category") or info.get("section") or info.get("domain") or "").strip().lower()
    if raw in SIM_SYSTEM_SECTION_KEYS:
        return raw
    if raw in {"cyber", "digital", "network", "it", "ot"}:
        return "digital"
    if raw in {"flow", "fluid"}:
        return "flow"
    if raw in {"function", "functional"}:
        return "function"
    if raw in {"physical", "process", "plant"}:
        return "physical"

    haystack = " ".join(
        str(value).lower()
        for value in (
            node_id,
            info.get("type"),
            info.get("module"),
            info.get("role"),
            info.get("name"),
        )
        if value
    )
    if any(hint in haystack for hint in CYBER_HINTS):
        return "digital"
    return "physical"


def _relation_label(value: Any, fallback: str = "link") -> str:
    text = str(value or "").strip()
    return text or str(fallback or "link")


def _sectioned_node_ids_by_type(data: Dict[str, Any], node_type: str) -> set[str]:
    node_ids: set[str] = set()
    for section in SIM_SYSTEM_SECTION_KEYS:
        section_payload = data.get(section)
        if not isinstance(section_payload, dict):
            continue
        for node_id, record in section_payload.items():
            if isinstance(record, dict) and str(record.get("type") or "") == node_type:
                node_ids.add(str(node_id))
    return node_ids


def _locate_sectioned_node(data: Dict[str, Any], node_id: str) -> Dict[str, Any] | None:
    for section in SIM_SYSTEM_SECTION_KEYS:
        section_payload = data.get(section)
        if not isinstance(section_payload, dict):
            continue
        record = section_payload.get(node_id)
        if isinstance(record, dict):
            return record
    return None


def _record_signal_sides(record: Dict[str, Any]) -> set[str]:
    sides: set[str] = set()
    for side in ("source", "target"):
        mapping = record.get(side)
        if not isinstance(mapping, dict):
            continue
        for key in mapping.keys():
            name = str(key).upper()
            if "_MAIN_" in name or name.startswith("S_MAIN_") or name.startswith("SD_MAIN_"):
                sides.add("main")
            if "_BACKUP_" in name or name.startswith("S_BACKUP_") or name.startswith("SD_BACKUP_"):
                sides.add("backup")
    return sides


def _apply_risk_service_digital_compat(node_id: str, raw_record: Dict[str, Any], record: Dict[str, Any]) -> None:
    node_type = _normalize_risk_service_digital_type(node_id, raw_record, record)
    record["type"] = node_type
    networks = dict(record.get("networks") or {})
    sides = _record_signal_sides(raw_record)

    if node_type == "PLC":
        record["source"] = {}
        record["target"] = {}
        lowered_id = node_id.lower()
        if "main" in lowered_id:
            sides = {"main"}
        elif "backup" in lowered_id:
            sides = {"backup"}
        if "main" in sides:
            networks["control_main_net"] = {}
            networks["mgmt_main_net"] = {}
        if "backup" in sides:
            networks["control_backup_net"] = {}
            networks["mgmt_backup_net"] = {}
    elif node_type in {"valve_ctrl", "heater_ctrl"}:
        record["source"] = {}
        if "main" in sides:
            networks["process_main_net"] = {}
        if "backup" in sides:
            networks["process_backup_net"] = {}
    elif node_type == "tr_press":
        record["target"] = {}
        if "main" in sides:
            networks["process_main_net"] = {}
        if "backup" in sides:
            networks["process_backup_net"] = {}

    if networks:
        record["networks"] = networks


def _normalize_risk_service_digital_type(node_id: str, raw_record: Dict[str, Any], record: Dict[str, Any]) -> str:
    raw_type = str(record.get("type") or raw_record.get("type") or "").strip()
    normalized_type = raw_type.lower().replace("-", "_").replace(" ", "_")
    mapped_type = RISK_SERVICE_DIGITAL_TYPE_ALIASES.get(normalized_type)
    if mapped_type:
        return mapped_type

    environment = raw_record.get("environment")
    haystack_parts = [
        node_id,
        raw_type,
        raw_record.get("name"),
        raw_record.get("label"),
        raw_record.get("role"),
        raw_record.get("module"),
        raw_record.get("description"),
    ]
    if isinstance(environment, dict):
        haystack_parts.extend(
            [
                environment.get("DEVICE_NAME"),
                environment.get("DEVICE_ROLE"),
                environment.get("DEVICE_DESC"),
            ]
        )
    haystack = " ".join(str(value).lower() for value in haystack_parts if value)

    if "firewall" in haystack:
        return "Firewall"
    if any(token in haystack for token in ("historian", "data historian", "data-historian")):
        return "DataHistorian"
    if any(token in haystack for token in ("database", "postgres", "mysql")):
        return "Database"
    if any(token in haystack for token in ("hmi", "scada")):
        return "HMI"
    if any(token in haystack for token in ("plc", "controller", "rtu", "ied", "dcs")):
        return "PLC"
    if any(token in haystack for token in ("network", " subnet", " vlan")) or node_id.lower().endswith("_net"):
        return "network"
    if any(token in haystack for token in ("computer", "desktop", "workstation", "server", "host", "engineer", "jump")):
        return "Computer"

    return raw_type
