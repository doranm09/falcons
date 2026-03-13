from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .pid_network import ExpectedNode, expected_cyber_nodes

DEFAULT_PURDUE_SUBNETS = {
    "L0/1": "172.30.0.0/24",
    "L2": "172.30.1.0/24",
    "L3": "172.30.2.0/24",
    "L3.5": "172.30.3.0/24",
    "L4": "172.30.4.0/24",
    "L5": "172.30.5.0/24",
}

PURDUE_HINTS = [
    ("L5", ["vendor", "portal", "enterprise", "business", "it", "office"]),
    ("L4", ["enterprise-app", "erp", "mes", "corp"]),
    ("L3.5", ["dmz", "remote", "broker", "update", "jump", "gateway", "proxy"]),
    ("L3", ["hist", "historian", "server", "scada", "engineering", "ops"]),
    ("L2", ["plc", "rtu", "controller", "ied", "dcs", "hmi"]),
    ("L0/1", ["sensor", "actuator", "field", "valve", "pump", "motor", "transmitter"]),
]


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


def _infer_purdue(label: str, role: str) -> Optional[str]:
    haystack = f"{label} {role}".lower()
    for tier, hints in PURDUE_HINTS:
        if any(hint in haystack for hint in hints):
            return tier
    return None


def _assign_ip(subnet: str, counters: Dict[str, int]) -> str:
    net = ipaddress.ip_network(subnet, strict=False)
    offset = counters.get(subnet, 10)
    counters[subnet] = offset + 1
    hosts = list(net.hosts())
    index = max(0, min(len(hosts) - 1, offset))
    return str(hosts[index])


def _next_conduit_ip(net: ipaddress._BaseNetwork, offset: int) -> Optional[str]:
    hosts = list(net.hosts())
    if not hosts:
        return None
    index = max(0, min(len(hosts) - 1, offset))
    return str(hosts[index])


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
    network_cidrs: Dict[str, Optional[ipaddress._BaseNetwork]] = {}

    inventory_assets: List[Dict[str, Any]] = []
    scanner_by_zone: Dict[str, str] = {}
    conduit_maps: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    conduit_ports: Dict[Tuple[str, str], List[int]] = {}
    conduit_ip_offsets: Dict[str, int] = {}

    node_by_id: Dict[str, ExpectedNode] = {node.node_id: node for node in expected_nodes}
    ip_by_id: Dict[str, str] = {}

    ip_counters: Dict[str, int] = {}

    for node in expected_nodes:
        info = variables.get(node.node_id, {}) if isinstance(variables, dict) else {}
        role = (info.get("type") if isinstance(info, dict) else None) or "cyber"
        inferred_purdue = node.purdue_level or _infer_purdue(node.label, str(role))
        zone = inferred_purdue or _zone_label(node)
        vlan_cidr = _validate_cidr(node.vlan_cidr) or _validate_cidr(DEFAULT_PURDUE_SUBNETS.get(zone))
        ip_addr = node.ip or ( _assign_ip(vlan_cidr, ip_counters) if vlan_cidr else None )
        if not ip_addr:
            continue
        ip_by_id[node.node_id] = ip_addr

        service_name = _sanitize(node.label or node.node_id)
        net_key = _network_key(
            ExpectedNode(
                node_id=node.node_id,
                label=node.label,
                domain=node.domain,
                ip=ip_addr,
                vlan=node.vlan,
                vlan_cidr=vlan_cidr,
                purdue_level=zone,
                redundancy_group=node.redundancy_group,
            )
        )

        if net_key not in networks:
            net_payload: Dict[str, Any] = {"internal": True}
            if vlan_cidr:
                net_payload["ipam"] = {"config": [{"subnet": vlan_cidr}]}
            networks[net_key] = net_payload
            network_cidrs[net_key] = ipaddress.ip_network(vlan_cidr, strict=False) if vlan_cidr else None

        port = _service_port(info if isinstance(info, dict) else {})
        protocol = _protocol(info if isinstance(info, dict) else {})

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
                net_key: {"ipv4_address": ip_addr},
            },
        }

        inventory_assets.append({
            "name": service_name,
            "role": str(role),
            "zone": zone,
            "ip": ip_addr,
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

    connections = sim_system.get("connections", []) if isinstance(sim_system, dict) else []
    for conn in connections:
        if not isinstance(conn, dict):
            continue
        src_id = str(conn.get("source") or "")
        tgt_id = str(conn.get("target") or "")
        if not src_id or not tgt_id:
            continue
        src_node = node_by_id.get(src_id)
        tgt_node = node_by_id.get(tgt_id)
        if not src_node or not tgt_node:
            continue
        src_ip = ip_by_id.get(src_id)
        tgt_ip = ip_by_id.get(tgt_id)
        if not src_ip or not tgt_ip:
            continue

        src_net = _network_key(src_node)
        tgt_net = _network_key(tgt_node)
        if src_net == tgt_net:
            continue

        src_info = variables.get(src_id, {}) if isinstance(variables, dict) else {}
        tgt_info = variables.get(tgt_id, {}) if isinstance(variables, dict) else {}
        target_port = _service_port(tgt_info if isinstance(tgt_info, dict) else {})

        key = tuple(sorted((src_net, tgt_net)))
        conduit_maps.setdefault(key, [])
        conduit_ports.setdefault(key, [])
        conduit_maps[key].append({
            "listen_port": target_port,
            "target_host": tgt_ip,
            "target_port": target_port,
        })
        if target_port not in conduit_ports[key]:
            conduit_ports[key].append(target_port)

    for (net_a, net_b), rules in conduit_maps.items():
        conduit_name = f"conduit-{net_a}-{net_b}"
        allowed_ports = ",".join(str(p) for p in sorted(conduit_ports.get((net_a, net_b), [])))
        env_map = json.dumps(rules, indent=2)

        networks_payload: Dict[str, Any] = {}
        for net_key in (net_a, net_b):
            net_obj = network_cidrs.get(net_key)
            if net_obj:
                offset = conduit_ip_offsets.get(net_key, 200)
                conduit_ip_offsets[net_key] = offset + 1
                ip_addr = _next_conduit_ip(net_obj, offset)
                if ip_addr:
                    networks_payload[net_key] = {"ipv4_address": ip_addr}
                    continue
            networks_payload[net_key] = {}

        services[conduit_name] = {
            "build": "./testbed/ot/conduit",
            "cap_add": ["NET_ADMIN"],
            "environment": {
                "ALLOWED_PORTS": allowed_ports,
                "CONDUIT_MAP": env_map,
                "LOG_PATH": f"/data/{conduit_name}.log",
                "FIXED_TIME": "2026-01-25T00:00:00Z",
            },
            "volumes": ["./testbed/ot/data:/data"],
            "networks": networks_payload,
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
