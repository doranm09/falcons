from typing import Dict, List, Tuple

from .models import Node, Vulnerability, ScanVulnerability


SEVERITY_EPSS = {
    "Critical": 0.9,
    "High": 0.7,
    "Medium": 0.4,
    "Low": 0.2,
}


def epss_from_cvss(score: float | None, fallback_severity: str | None = None) -> float:
    if score is not None:
        return max(0.05, min(score / 10.0, 0.95))
    if fallback_severity:
        return SEVERITY_EPSS.get(fallback_severity, 0.1)
    return 0.1


def build_cyber_data_for_risk_nodes(risk_nodes: List[str]) -> Tuple[Dict, List[Dict]]:
    """Build cyber.json payload and return a node mapping list."""
    scanned_nodes = []
    mapped_nodes = []

    risk_set = set(risk_nodes)
    nodes = Node.objects.all().order_by("ip_address")

    for node in nodes:
        node_id = None
        if node.name and node.name in risk_set:
            node_id = node.name
        elif node.ip_address and node.ip_address in risk_set:
            node_id = node.ip_address

        mapped_nodes.append({
            "node_id": node.id,
            "name": node.name,
            "ip_address": node.ip_address,
            "risk_node_id": node_id,
        })

        if not node_id:
            continue

        vulnerabilities = []

        # Global vulnerabilities tied to Node
        for vuln in Vulnerability.objects.filter(nodes=node):
            epss = epss_from_cvss(vuln.score, vuln.severity)
            vulnerabilities.append({
                "id": vuln.cve_id,
                "epss": epss,
            })

        # Scan-specific vulnerabilities tied by host IP
        if node.ip_address:
            for scan_vuln in ScanVulnerability.objects.filter(host_ip=node.ip_address):
                epss = epss_from_cvss(scan_vuln.cvss_score, scan_vuln.severity)
                vulnerabilities.append({
                    "id": scan_vuln.cve_id,
                    "epss": epss,
                })

        # Deduplicate by CVE, keep max epss
        vuln_map = {}
        for vuln in vulnerabilities:
            cve = vuln["id"]
            epss = vuln["epss"]
            vuln_map[cve] = max(vuln_map.get(cve, 0), epss)

        vuln_list = [{"id": cve, "epss": epss} for cve, epss in vuln_map.items()]
        vuln_list.sort(key=lambda v: v["epss"], reverse=True)
        vuln_list = vuln_list[:10]

        scanned_nodes.append({
            "id": node_id,
            "type": "network_node",
            "vulnerability": vuln_list,
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
