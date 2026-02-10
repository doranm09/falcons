from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .pid_system import classify_domain, extract_ip


@dataclass
class ExpectedNode:
    node_id: str
    label: str
    domain: str
    ip: Optional[str]
    vlan: Optional[str]
    vlan_cidr: Optional[str]
    purdue_level: Optional[str]
    redundancy_group: Optional[str]


def _coerce_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_vlan(info: Dict[str, Any]) -> Optional[str]:
    for key in ("vlan", "vlan_id", "vlan_tag"):
        value = _coerce_str(info.get(key))
        if value:
            return value
    return None


def _extract_vlan_cidr(info: Dict[str, Any]) -> Optional[str]:
    for key in ("vlan_cidr", "subnet", "cidr"):
        value = _coerce_str(info.get(key))
        if value:
            return value
    return None


def _extract_purdue(info: Dict[str, Any]) -> Optional[str]:
    for key in ("purdue_level", "purdue", "tier", "level"):
        value = _coerce_str(info.get(key))
        if value:
            return value
    return None


def _extract_redundancy(info: Dict[str, Any]) -> Optional[str]:
    for key in ("redundancy_group", "redundant_group", "redundancy"):
        value = _coerce_str(info.get(key))
        if value:
            return value
    return None


def expected_cyber_nodes(sim_system: Dict[str, Any]) -> List[ExpectedNode]:
    variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
    nodes: List[ExpectedNode] = []

    for var_id, info in variables.items():
        info = info if isinstance(info, dict) else {}
        domain = classify_domain(str(var_id), info)
        if domain != "cyber":
            continue

        label = _coerce_str(info.get("name") or info.get("label") or var_id) or str(var_id)
        ip = extract_ip(info)
        vlan = _extract_vlan(info)
        vlan_cidr = _extract_vlan_cidr(info)
        purdue = _extract_purdue(info)
        redundancy = _extract_redundancy(info)

        nodes.append(
            ExpectedNode(
                node_id=str(var_id),
                label=label,
                domain=domain,
                ip=ip,
                vlan=vlan,
                vlan_cidr=vlan_cidr,
                purdue_level=purdue,
                redundancy_group=redundancy,
            )
        )

    return nodes


def summarize_expected_nodes(nodes: Iterable[ExpectedNode]) -> Dict[str, Any]:
    nodes = list(nodes)
    vlan_counts = defaultdict(int)
    vlan_cidrs = defaultdict(set)
    purdue_counts = defaultdict(int)
    redundancy_counts = defaultdict(int)

    for node in nodes:
        if node.vlan:
            vlan_counts[node.vlan] += 1
        if node.vlan and node.vlan_cidr:
            vlan_cidrs[node.vlan].add(node.vlan_cidr)
        if node.purdue_level:
            purdue_counts[node.purdue_level] += 1
        if node.redundancy_group:
            redundancy_counts[node.redundancy_group] += 1

    return {
        "count": len(nodes),
        "vlans": {key: vlan_counts[key] for key in sorted(vlan_counts)},
        "vlan_cidrs": {key: sorted(list(vlan_cidrs[key])) for key in sorted(vlan_cidrs)},
        "purdue_levels": {key: purdue_counts[key] for key in sorted(purdue_counts)},
        "redundancy_groups": {key: redundancy_counts[key] for key in sorted(redundancy_counts)},
    }


def validate_expected_nodes(
    expected: Iterable[ExpectedNode],
    discovered_ips: Iterable[str],
) -> Dict[str, Any]:
    expected = list(expected)
    discovered = {str(ip) for ip in discovered_ips if ip}

    missing = []
    found = []
    unknown = []

    expected_ips = {node.ip for node in expected if node.ip}
    for node in expected:
        if not node.ip:
            missing.append({
                "id": node.node_id,
                "label": node.label,
                "reason": "missing_ip",
            })
            continue
        if node.ip in discovered:
            found.append({
                "id": node.node_id,
                "label": node.label,
                "ip": node.ip,
                "vlan": node.vlan,
                "purdue_level": node.purdue_level,
                "redundancy_group": node.redundancy_group,
            })
        else:
            missing.append({
                "id": node.node_id,
                "label": node.label,
                "ip": node.ip,
                "vlan": node.vlan,
                "purdue_level": node.purdue_level,
                "redundancy_group": node.redundancy_group,
                "reason": "not_discovered",
            })

    for ip in sorted(discovered - expected_ips):
        unknown.append(ip)

    return {
        "expected_count": len(expected),
        "expected_with_ip": len(expected_ips),
        "found": found,
        "missing": missing,
        "unknown_ips": unknown,
    }
