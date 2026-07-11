import ipaddress
import re
from typing import Dict, List, Tuple

from .models import Node, RiskNodeMapping, Vulnerability, ScanVulnerability


SEVERITY_EPSS = {
    "Critical": 0.9,
    "High": 0.7,
    "Medium": 0.4,
    "Low": 0.2,
}

OOB_MANAGEMENT_PREFIXES = ("172.31.250.",)


def epss_from_cvss(score: float | None, fallback_severity: str | None = None) -> float:
    if score is not None:
        return max(0.05, min(score / 10.0, 0.95))
    if fallback_severity:
        return SEVERITY_EPSS.get(fallback_severity, 0.1)
    return 0.1


def _normalize_risk_identity(value: str = "") -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _is_oob_management_ip(ip_text: str = "") -> bool:
    text = str(ip_text or "").strip()
    return any(text.startswith(prefix) for prefix in OOB_MANAGEMENT_PREFIXES)


def _node_ip_rank(ip_text: str) -> tuple[int, str]:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return (99, ip_text)
    if ip_obj.version != 4:
        return (98, ip_text)
    if ip_text.startswith("10."):
        return (0, ip_text)
    if ip_text.startswith("192.168."):
        return (1, ip_text)
    if ip_obj.is_private:
        return (2, ip_text)
    return (3, ip_text)


def risk_candidate_node_ips(node: Node, include_oob: bool = False) -> list[str]:
    ips = []

    def _append_ip(ip_value: str) -> None:
        ip_text = str(ip_value or "").strip()
        if not ip_text or ip_text.startswith("127.") or ip_text == "::1":
            return
        if not include_oob and _is_oob_management_ip(ip_text):
            return
        if ip_text not in ips:
            ips.append(ip_text)

    _append_ip(getattr(node, "ip_address", ""))
    for iface in getattr(node, "interfaces", []).all():
        _append_ip(getattr(iface, "ip", ""))
    return sorted(ips, key=_node_ip_rank)


def preferred_risk_node_ip(node: Node) -> str:
    preferred = risk_candidate_node_ips(node, include_oob=False)
    if preferred:
        return preferred[0]
    fallback = risk_candidate_node_ips(node, include_oob=True)
    if fallback:
        return fallback[0]
    return str(getattr(node, "ip_address", "") or "").strip()


def _hybrid_topology_records() -> list[dict]:
    try:
        from . import views as dashboard_views
    except Exception:
        return []
    return list(getattr(dashboard_views, "IAEA_TESTBED_STATIC_TOPOLOGY", []) or [])


def _hybrid_record_tokens(record: dict) -> list[str]:
    tokens = [
        str(record.get("hostname", "")).strip(),
        str(record.get("label", "")).strip(),
    ]
    tokens.extend(str(alias).strip() for alias in record.get("aliases", []) or [])
    tokens.extend(
        str(ip_text).strip()
        for ip_text in record.get("ip_addresses", []) or []
        if ip_text and not _is_oob_management_ip(str(ip_text))
    )
    return [token for token in tokens if token]


def _hybrid_record_for_identity(value: str = "") -> dict | None:
    normalized = _normalize_risk_identity(value)
    raw = str(value or "").strip()
    if not normalized and not raw:
        return None
    for record in _hybrid_topology_records():
        tokens = _hybrid_record_tokens(record)
        if raw and raw in tokens:
            return record
        if normalized and any(_normalize_risk_identity(token) == normalized for token in tokens):
            return record
    return None


def _match_risk_node_from_tokens(tokens: list[str], risk_nodes: List[str]) -> str | None:
    risk_set = {str(risk_node) for risk_node in risk_nodes}
    risk_by_normalized = {
        _normalize_risk_identity(risk_node): str(risk_node)
        for risk_node in risk_nodes
        if _normalize_risk_identity(risk_node)
    }
    for token in tokens:
        token_text = str(token or "").strip()
        if not token_text:
            continue
        if token_text in risk_set:
            return token_text
        normalized = _normalize_risk_identity(token_text)
        if normalized and normalized in risk_by_normalized:
            return risk_by_normalized[normalized]
    return None


def _auto_match_allowed(node: Node) -> bool:
    return bool(risk_candidate_node_ips(node, include_oob=False))


def _resolve_risk_node_id_for_node(
    node: Node,
    risk_nodes: List[str],
    mapping_by_node_id: dict,
    mapping_by_ip: dict,
) -> str | None:
    mapping = mapping_by_node_id.get(node.id)
    if mapping:
        return mapping.risk_node_id

    for ip_text in risk_candidate_node_ips(node, include_oob=True):
        explicit = mapping_by_ip.get(ip_text)
        if explicit:
            return explicit.risk_node_id

    if not _auto_match_allowed(node):
        return None

    direct_tokens = [str(getattr(node, "name", "") or "").strip(), *risk_candidate_node_ips(node, include_oob=False)]
    direct_match = _match_risk_node_from_tokens(direct_tokens, risk_nodes)
    if direct_match:
        return direct_match

    hybrid_record = None
    for token in direct_tokens:
        hybrid_record = _hybrid_record_for_identity(token)
        if hybrid_record:
            break
    if hybrid_record:
        hybrid_match = _match_risk_node_from_tokens(_hybrid_record_tokens(hybrid_record), risk_nodes)
        if hybrid_match:
            return hybrid_match

    return None


def _mapping_score_for_risk_node(node: Node, risk_node_id: str, hybrid_record: dict | None) -> tuple[int, str] | None:
    in_band_ips = risk_candidate_node_ips(node, include_oob=False)
    if not in_band_ips:
        return None

    risk_text = str(risk_node_id or "").strip()
    risk_normalized = _normalize_risk_identity(risk_text)
    node_name = str(getattr(node, "name", "") or "").strip()
    node_name_normalized = _normalize_risk_identity(node_name)

    if risk_text and risk_text in in_band_ips:
        return (0, "matched in-band IP")
    if risk_normalized and node_name_normalized == risk_normalized:
        return (1, "matched node name")

    if hybrid_record:
        record_ips = {
            str(ip_text).strip()
            for ip_text in hybrid_record.get("ip_addresses", []) or []
            if ip_text and not _is_oob_management_ip(str(ip_text))
        }
        if record_ips.intersection(in_band_ips):
            return (2, "matched validated hybrid IP")
        record_tokens = {_normalize_risk_identity(token) for token in _hybrid_record_tokens(hybrid_record)}
        if node_name_normalized and node_name_normalized in record_tokens:
            return (3, "matched validated hybrid hostname")

    return None


def suggest_risk_node_mappings(risk_nodes: List[str], candidate_nodes: List[Node] | None = None) -> Dict[str, Dict]:
    if candidate_nodes is None:
        candidate_nodes = list(Node.objects.all().prefetch_related("interfaces").order_by("-id"))
    else:
        candidate_nodes = list(candidate_nodes)

    explicit_mappings = {
        mapping.risk_node_id
        for mapping in RiskNodeMapping.objects.filter(risk_node_id__in=risk_nodes, active=True)
    }
    suggestions: Dict[str, Dict] = {}
    used_node_ids = set()

    for risk_node_id in risk_nodes:
        if risk_node_id in explicit_mappings:
            continue
        hybrid_record = _hybrid_record_for_identity(risk_node_id)
        best_match: tuple[int, str, Node] | None = None
        for node in candidate_nodes:
            if node.id in used_node_ids:
                continue
            scored = _mapping_score_for_risk_node(node, risk_node_id, hybrid_record)
            if not scored:
                continue
            score, reason = scored
            if best_match is None or score < best_match[0]:
                best_match = (score, reason, node)

        if not best_match:
            continue

        _, reason, node = best_match
        suggestions[str(risk_node_id)] = {
            "risk_node_id": str(risk_node_id),
            "node_id": node.id,
            "node_name": node.name,
            "ip_address": preferred_risk_node_ip(node),
            "label": (hybrid_record or {}).get("label") or node.name or str(risk_node_id),
            "notes": "Auto-suggested from validated hybrid topology",
            "active": True,
            "reason": reason,
        }
        used_node_ids.add(node.id)

    return suggestions


def build_cyber_data_for_risk_nodes(
    risk_nodes: List[str],
    scan_run_id: int | None = None,
) -> Tuple[Dict, List[Dict]]:
    """Build cyber.json payload and return a node mapping list."""
    scanned_nodes = []
    mapped_nodes = []

    risk_set = set(risk_nodes)
    nodes = Node.objects.all()
    if scan_run_id is not None:
        nodes = nodes.filter(scan_run_id=scan_run_id)
    nodes = nodes.prefetch_related("interfaces").order_by("-id")

    mappings = list(
        RiskNodeMapping.objects.filter(risk_node_id__in=risk_nodes, active=True).select_related("node")
    )
    mapping_by_node_id = {mapping.node_id: mapping for mapping in mappings if mapping.node_id}
    mapping_by_ip = {}
    for mapping in mappings:
        if mapping.ip_address:
            mapping_by_ip[mapping.ip_address] = mapping
        if mapping.node_id and mapping.node and mapping.node.ip_address:
            mapping_by_ip[mapping.node.ip_address] = mapping

    def resolve_risk_node_id(node: Node) -> str | None:
        mapping = mapping_by_node_id.get(node.id)
        if not mapping and node.ip_address:
            mapping = mapping_by_ip.get(node.ip_address)
        if mapping:
            return mapping.risk_node_id
        if node.name and node.name in risk_set:
            return node.name
        if node.ip_address and node.ip_address in risk_set:
            return node.ip_address
        return None

    def is_mapped(node: Node) -> bool:
        return resolve_risk_node_id(node) is not None

    selected_nodes = []
    selected_by_ip = {}
    selected_by_name = {}

    for node in nodes:
        if node.ip_address:
            current = selected_by_ip.get(node.ip_address)
            if current is None or (is_mapped(node) and not is_mapped(current)):
                selected_by_ip[node.ip_address] = node
            continue
        if node.name:
            current = selected_by_name.get(node.name)
            if current is None or (is_mapped(node) and not is_mapped(current)):
                selected_by_name[node.name] = node

    selected_nodes.extend(selected_by_ip.values())
    selected_nodes.extend(selected_by_name.values())

    for node in selected_nodes:
        vulnerabilities = []

        # Global vulnerabilities tied to Node
        for vuln in Vulnerability.objects.filter(nodes=node):
            epss = epss_from_cvss(vuln.score, vuln.severity)
            vulnerabilities.append({
                "id": vuln.cve_id,
                "epss": epss,
                "source": "node",
            })

        # Scan-specific vulnerabilities tied by host IP
        if node.ip_address:
            scan_vulns = ScanVulnerability.objects.filter(host_ip=node.ip_address)
            if scan_run_id is not None:
                scan_vulns = scan_vulns.filter(scan_run_id=scan_run_id)
            for scan_vuln in scan_vulns:
                epss = epss_from_cvss(scan_vuln.cvss_score, scan_vuln.severity)
                vulnerabilities.append({
                    "id": scan_vuln.cve_id,
                    "epss": epss,
                    "source": "scan",
                })

        # Deduplicate by CVE, keep max epss and aggregate evidence source.
        vuln_map = {}
        for vuln in vulnerabilities:
            cve = vuln["id"]
            entry = vuln_map.setdefault(cve, {"id": cve, "epss": 0.0, "sources": set()})
            entry["epss"] = max(entry["epss"], vuln["epss"])
            source = vuln.get("source")
            if source:
                entry["sources"].add(str(source))

        vuln_list = [
            {
                "id": cve,
                "epss": entry["epss"],
                "sources": sorted(entry["sources"]),
            }
            for cve, entry in vuln_map.items()
        ]
        vuln_list.sort(key=lambda v: v["epss"], reverse=True)
        top_vulns = vuln_list[:10]

        node_id = _resolve_risk_node_id_for_node(node, risk_nodes, mapping_by_node_id, mapping_by_ip)
        mapped_nodes.append({
            "node_id": node.id,
            "name": node.name,
            "ip_address": preferred_risk_node_ip(node),
            "risk_node_id": node_id,
            "vulnerability_count": len(vuln_list),
            "vulnerabilities": top_vulns,
            "has_vulnerabilities": bool(vuln_list),
        })

        if not node_id:
            continue

        scanned_nodes.append({
            "id": node_id,
            "type": "network_node",
            "vulnerability": top_vulns,
        })

    return {"scanned_nodes": scanned_nodes}, mapped_nodes


def summarize_risk_results(mapped_nodes: List[Dict], results: Dict) -> List[Dict]:
    summary = []
    for node in mapped_nodes:
        risk_node_id = node.get("risk_node_id")
        risk_result = results.get(risk_node_id) if risk_node_id else None
        compromised = None
        if risk_result:
            compromised = risk_result.get("compromised") or risk_result.get("faulty")
            if compromised is None:
                compromised = max(risk_result.values()) if risk_result else None

        risk_score = float(compromised) if compromised is not None else None
        risk_level = "unknown"
        if risk_score is not None:
            if risk_score >= 0.7:
                risk_level = "high"
            elif risk_score >= 0.4:
                risk_level = "medium"
            else:
                risk_level = "low"

        summary.append({
            **node,
            "risk_result": risk_result,
            "risk_score": risk_score,
            "risk_level": risk_level,
        })

    return summary
