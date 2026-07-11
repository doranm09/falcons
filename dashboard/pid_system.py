from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from django.utils.timezone import now

from .models import NetworkConnection
from .sim_system import load_local_sim_system

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
    "camera",
)

DOMAIN_ALIASES = {
    "cyber": "cyber",
    "network": "cyber",
    "it": "cyber",
    "ot": "cyber",
    "physical": "physical",
    "process": "physical",
    "plant": "physical",
}

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def resolve_sim_system_path(
    source: str,
    output_dir: Path,
    target_path: Optional[Path],
) -> Tuple[Optional[Path], str]:
    source = (source or "").lower()
    current_path = output_dir / "sim_system.json"
    if source == "target":
        if target_path and target_path.exists():
            return target_path, "target"
        return None, "target"

    if source == "latest":
        latest = _latest_sim_system_file(output_dir)
        return (latest, "latest") if latest else (None, "latest")

    if target_path and target_path.exists():
        return target_path, "target"

    if current_path.exists():
        return current_path, "current"

    latest = _latest_sim_system_file(output_dir)
    return (latest, "latest") if latest else (None, "current")


def load_sim_system_file(path: Path) -> Dict[str, Any]:
    return load_local_sim_system(path)


def build_system_elements(
    sim_system: Dict[str, Any],
    include_network: bool = True,
    network_window_minutes: int = 60,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
    connections = sim_system.get("connections", []) if isinstance(sim_system, dict) else []

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    ip_to_node: Dict[str, str] = {}
    agent_to_node: Dict[str, str] = {}

    cyber_nodes = set()
    physical_nodes = set()

    def _shorten_label(value: str, max_len: int = 28) -> str:
        value = value.strip()
        if len(value) <= max_len:
            return value
        return f"{value[: max_len - 1]}…"

    def add_node(node_id: str, payload: Dict[str, Any]) -> None:
        if node_id in nodes:
            return
        nodes[node_id] = payload

    for var_id, info in variables.items():
        info = info if isinstance(info, dict) else {}
        raw_label = (
            info.get("name")
            or info.get("label")
            or info.get("title")
            or str(var_id)
        )
        raw_label = str(raw_label)
        node_type = info.get("type") or "unknown"
        domain = classify_domain(var_id, info)
        node_payload = {
            "id": str(var_id),
            "label": raw_label,
            "label_short": _shorten_label(raw_label),
            "label_full": raw_label,
            "domain": domain,
            "type": node_type,
            "module": info.get("module") or "",
        }

        for key in ("system", "unit", "description", "vlan", "vlan_cidr", "purdue_level", "redundancy_group"):
            if info.get(key):
                node_payload[key] = info.get(key)

        ip_address = extract_ip(info)
        if ip_address:
            node_payload["ip"] = ip_address
            if domain == "cyber":
                ip_to_node[ip_address] = str(var_id)

        agent_id = str(info.get("agent_id") or "").strip()
        if agent_id:
            node_payload["agent_id"] = agent_id
            if domain == "cyber":
                agent_to_node[agent_id] = str(var_id)

        add_node(str(var_id), node_payload)

        if domain == "cyber":
            cyber_nodes.add(str(var_id))
        else:
            physical_nodes.add(str(var_id))

    edge_count = 0
    for conn in connections:
        if not isinstance(conn, dict):
            continue
        source = conn.get("source")
        target = conn.get("target")
        if source is None or target is None:
            continue
        s_attr = str(conn.get("s_attr") or "")
        t_attr = str(conn.get("t_attr") or "")
        label = _format_edge_label(s_attr, t_attr)
        edge_id = f"process:{edge_count}"
        edge_count += 1
        edges.append(
            {
                "data": {
                    "id": edge_id,
                    "source": str(source),
                    "target": str(target),
                    "label": label,
                    "kind": "process",
                }
            }
        )

    network_edges = 0
    cyber_connected: set[str] = set()

    if include_network:
        network_edges, cyber_connected = _append_network_edges(
            nodes,
            edges,
            ip_to_node,
            agent_to_node,
            network_window_minutes,
        )

    for node_id in cyber_nodes:
        nodes[node_id]["cyber_connected"] = node_id in cyber_connected

    elements = [{"data": payload} for payload in nodes.values()] + edges
    meta = {
        "variables": len(variables),
        "connections": len(connections),
        "network_edges": network_edges,
        "cyber_nodes": len(cyber_nodes),
        "physical_nodes": len(physical_nodes),
        "unconnected_cyber": sorted([n for n in cyber_nodes if n not in cyber_connected]),
    }

    return elements, meta


def classify_domain(var_id: str, info: Dict[str, Any]) -> str:
    raw_domain = (
        info.get("domain")
        or info.get("layer")
        or info.get("category")
        or info.get("kind")
        or info.get("classification")
    )
    if isinstance(raw_domain, str):
        normalized = DOMAIN_ALIASES.get(raw_domain.strip().lower())
        if normalized:
            return normalized

    haystack = " ".join(
        str(value).lower()
        for value in (
            var_id,
            info.get("type"),
            info.get("module"),
            info.get("role"),
            info.get("name"),
        )
        if value
    )

    for hint in CYBER_HINTS:
        if hint in haystack:
            return "cyber"

    return "physical"


def extract_ip(info: Dict[str, Any]) -> Optional[str]:
    for key in ("ip", "ip_address", "address", "host_ip", "network_ip"):
        value = info.get(key)
        if isinstance(value, str) and IPV4_RE.match(value.strip()):
            return value.strip()
    ip_list = info.get("ip_addresses")
    if isinstance(ip_list, list) and ip_list:
        value = ip_list[0]
        if isinstance(value, str) and IPV4_RE.match(value.strip()):
            return value.strip()
    return None


def _append_network_edges(
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    ip_to_node: Dict[str, str],
    agent_to_node: Dict[str, str],
    network_window_minutes: int,
) -> Tuple[int, set[str]]:
    flows = defaultdict(int)
    cyber_connected: set[str] = set()

    cutoff = now() - timedelta(minutes=network_window_minutes)
    connections = NetworkConnection.objects.filter(last_seen__gte=cutoff).select_related("agent")

    for conn in connections:
        if not conn.remote_address or conn.remote_address in ("127.0.0.1", "localhost", "::1"):
            continue

        agent_id = conn.agent.agent_id if conn.agent else ""
        src_node = agent_to_node.get(agent_id)
        if not src_node and conn.agent and conn.agent.ip_address:
            src_node = ip_to_node.get(conn.agent.ip_address)

        if not src_node:
            src_node = f"agent:{agent_id or 'unknown'}"
            if src_node not in nodes:
                nodes[src_node] = {
                    "id": src_node,
                    "label": conn.agent.hostname if conn.agent else src_node,
                    "domain": "cyber",
                    "type": "agent",
                    "module": "network",
                    "agent_id": agent_id,
                    "ip": conn.agent.ip_address if conn.agent else "",
                }

        dst_node = ip_to_node.get(conn.remote_address)
        if not dst_node:
            dst_node = f"ip:{conn.remote_address}"
            if dst_node not in nodes:
                nodes[dst_node] = {
                    "id": dst_node,
                    "label": conn.remote_address,
                    "domain": "cyber",
                    "type": "external",
                    "module": "network",
                    "ip": conn.remote_address,
                }

        flow_key = (src_node, dst_node, conn.protocol or "")
        flows[flow_key] += 1

    for (src_node, dst_node, protocol), count in flows.items():
        edge_id = f"network:{src_node}->{dst_node}:{protocol}"
        edges.append(
            {
                "data": {
                    "id": edge_id,
                    "source": src_node,
                    "target": dst_node,
                    "label": f"{protocol} ({count})" if protocol else f"net ({count})",
                    "kind": "network",
                }
            }
        )
        cyber_connected.add(src_node)
        cyber_connected.add(dst_node)

    return len(flows), cyber_connected


def _latest_sim_system_file(output_dir: Path) -> Optional[Path]:
    if not output_dir.exists():
        return None
    candidates = sorted(output_dir.glob("*_sim_system.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _format_edge_label(s_attr: str, t_attr: str) -> str:
    if s_attr and t_attr:
        return f"{s_attr}->{t_attr}"
    if s_attr:
        return s_attr
    if t_attr:
        return t_attr
    return ""
