from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .pid_network import ExpectedNode, expected_cyber_nodes


@dataclass
class TestbedFiles:
    compose_path: Path
    inventory_path: Path


def _sanitize(name: str) -> str:
    safe = []
    for ch in name.lower():
        if ch.isalnum() or ch in ("-", "_"):
            safe.append(ch)
        else:
            safe.append("-")
    cleaned = "".join(safe).strip("-")
    return cleaned or "node"


def _service_port(info: Dict[str, Any]) -> int:
    for key in ("service_port", "port", "listen_port"):
        value = info.get(key)
        try:
            if value is not None:
                port = int(value)
                if 1 <= port <= 65535:
                    return port
        except (TypeError, ValueError):
            continue
    return 8080


def _protocol(info: Dict[str, Any]) -> str:
    for key in ("protocol", "protocol_name"):
        value = info.get(key)
        if value:
            return str(value)
    return "http"


def _network_key(node: ExpectedNode) -> str:
    if node.vlan:
        return f"vlan-{_sanitize(node.vlan)}"
    if node.purdue_level:
        return f"zone-{_sanitize(node.purdue_level)}"
    return "zone-cyber"


def _zone_label(node: ExpectedNode) -> str:
    return node.purdue_level or node.vlan or "cyber"


def _validate_cidr(cidr: Optional[str]) -> Optional[str]:
    if not cidr:
        return None
    try:
        ipaddress.ip_network(cidr, strict=False)
        return cidr
    except ValueError:
        return None


def build_testbed_from_sim_system(
    sim_system: Dict[str, Any],
    output_dir: Path,
    compose_name: str = "pid_testbed.compose.yml",
    inventory_name: str = "pid_inventory.json",
) -> TestbedFiles:
    output_dir.mkdir(parents=True, exist_ok=True)
    compose_path = output_dir / compose_name
    inventory_path = output_dir / inventory_name

    variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
    expected_nodes = expected_cyber_nodes(sim_system)

    services: Dict[str, Any] = {}
    networks: Dict[str, Any] = {}

    inventory_assets: List[Dict[str, Any]] = []
    scanner_by_zone: Dict[str, str] = {}

    for node in expected_nodes:
        info = variables.get(node.node_id, {}) if isinstance(variables, dict) else {}
        if not node.ip:
            continue
        service_name = _sanitize(node.label or node.node_id)
        zone = _zone_label(node)
        net_key = _network_key(node)
        vlan_cidr = _validate_cidr(node.vlan_cidr)

        if net_key not in networks:
            net_payload: Dict[str, Any] = {"internal": True}
            if vlan_cidr:
                net_payload["ipam"] = {"config": [{"subnet": vlan_cidr}]}
            networks[net_key] = net_payload

        port = _service_port(info if isinstance(info, dict) else {})
        protocol = _protocol(info if isinstance(info, dict) else {})
        role = (info.get("type") if isinstance(info, dict) else None) or "cyber"

        services[service_name] = {
            "image": "python:3.11-slim",
            "command": ["python", "/app/service.py"],
            "environment": {
                "SERVICE_NAME": service_name,
                "SERVICE_ROLE": str(role),
                "SERVICE_ZONE": zone,
                "SERVICE_PORT": str(port),
                "PROTOCOL_NAME": protocol,
                "LOG_PATH": f"/data/{service_name}.log",
                "FIXED_TIME": "2026-01-25T00:00:00Z",
            },
            "volumes": [
                "./testbed/ot/services:/app",
                "./testbed/ot/data:/data",
            ],
            "networks": {
                net_key: {"ipv4_address": node.ip},
            },
        }

        inventory_assets.append({
            "name": service_name,
            "role": str(role),
            "zone": zone,
            "ip": node.ip,
            "port": port,
            "protocol": protocol,
        })

        scanner_key = _sanitize(zone)
        if scanner_key not in scanner_by_zone:
            scanner_name = f"scanner-{scanner_key}"
            scanner_by_zone[scanner_key] = scanner_name
            services[scanner_name] = {
                "image": "python:3.11-slim",
                "command": ["python", "/scanner/scanner.py"],
                "environment": {
                    "SCAN_ZONE": zone,
                    "INVENTORY_PATH": "/workspace/inventory.json",
                    "OUT_PATH": f"/data/scans/scan-{scanner_key}.json",
                    "FIXED_TIME": "2026-01-25T00:00:00Z",
                    "POLL_INTERVAL": "30",
                },
                "volumes": [
                    "./testbed/ot/scanner:/scanner",
                    f"{inventory_path.as_posix()}:/workspace/inventory.json:ro",
                    "./testbed/ot/data:/data",
                ],
                "networks": {
                    net_key: {},
                },
            }

    inventory_payload = {
        "run_id": "pid-testbed",
        "assets": inventory_assets,
    }
    inventory_path.write_text(json.dumps(inventory_payload, indent=2) + "\n", encoding="utf-8")

    compose_payload = {
        "services": services,
        "networks": networks,
    }
    compose_path.write_text(_dump_yaml(compose_payload), encoding="utf-8")

    return TestbedFiles(compose_path=compose_path, inventory_path=inventory_path)


def _dump_yaml(payload: Dict[str, Any], indent: int = 0) -> str:
    lines: List[str] = []

    def write_line(text: str) -> None:
        lines.append(" " * indent + text)

    def dump_value(value: Any, level: int) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                prefix = " " * level + f"{key}:"
                if isinstance(val, (dict, list)):
                    lines.append(prefix)
                    dump_value(val, level + 2)
                else:
                    lines.append(prefix + f" {json.dumps(val)}")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    lines.append(" " * level + "-")
                    dump_value(item, level + 2)
                else:
                    lines.append(" " * level + f"- {json.dumps(item)}")
        else:
            lines.append(" " * level + json.dumps(value))

    dump_value(payload, indent)
    return "\n".join(lines) + "\n"
