import ipaddress
import re
from typing import Dict, List, Tuple

from .gvmd import fetch_gvmd_findings_for_ips
from .models import Node, RiskNodeMapping, Vulnerability, ScanVulnerability


SEVERITY_EPSS = {
    "Critical": 0.9,
    "High": 0.7,
    "Medium": 0.4,
    "Low": 0.2,
}

OOB_MANAGEMENT_PREFIXES = ("172.31.250.",)
RISK_VULNERABILITY_BUCKET_ALIASES = {
    "vul_tech": "vul_tech",
    "vul_tech1": "vul_tech1",
    "vul_tech2": "vul_tech2",
    "vul_tech3": "vul_tech3",
    "compromise": "vul_tech2",
    "compromised": "vul_tech2",
    "cyber": "vul_tech2",
    "fault": "vul_tech3",
    "faulty": "vul_tech3",
    "availability": "vul_tech3",
    "dos": "vul_tech3",
}
PLC_COMPROMISE_BUCKET_HINT = "vul_tech2"
PLC_FAULT_BUCKET_HINT = "vul_tech3"
PLC_FAULT_BUCKET_PATTERNS = (
    r"\bdenial(?:[ -]?of[ -]?service)?\b",
    r"\bdos\b",
    r"\bcrash(?:es|ed|ing)?\b",
    r"\bhang(?:s|ing)?\b",
    r"\breboot(?:s|ed|ing)?\b",
    r"\bdeadlock\b",
    r"\bresource exhaustion\b",
    r"\bavailability\b",
    r"\bwatchdog\b",
    r"\boutage\b",
)


def epss_from_cvss(score: float | None, fallback_severity: str | None = None) -> float:
    if score is not None:
        return max(0.05, min(score / 10.0, 0.95))
    if fallback_severity:
        return SEVERITY_EPSS.get(fallback_severity, 0.1)
    return 0.1


def _normalize_risk_identity(value: str = "") -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def normalize_risk_vulnerability_bucket_hint(value: str = "") -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    normalized = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return RISK_VULNERABILITY_BUCKET_ALIASES.get(normalized, "")


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


def _is_plc_risk_node(risk_node_id: str = "", node: Node | None = None) -> bool:
    candidates = [str(risk_node_id or "").strip()]
    record = _hybrid_record_for_identity(risk_node_id)
    if record:
        candidates.extend(_hybrid_record_tokens(record))
        candidates.append(str(record.get("role_label") or "").strip())
    if node is not None:
        candidates.extend(
            [
                str(getattr(node, "name", "") or "").strip(),
                str(getattr(node, "hostname", "") or "").strip(),
                str(getattr(node, "description", "") or "").strip(),
            ]
        )
    return any("plc" in str(candidate).lower() for candidate in candidates if str(candidate).strip())


def classify_risk_finding_bucket(
    risk_node_id: str = "",
    vulnerability: dict | None = None,
    *,
    node: Node | None = None,
) -> str | None:
    record = vulnerability if isinstance(vulnerability, dict) else {}
    explicit = normalize_risk_vulnerability_bucket_hint(
        record.get("bucket_hint")
        or record.get("bucket")
        or record.get("risk_bucket")
        or record.get("vulnerability_bucket")
    )
    if explicit:
        return explicit
    if not _is_plc_risk_node(risk_node_id, node=node):
        return None

    text = " ".join(
        str(record.get(field_name) or "").strip()
        for field_name in ("cve", "cve_id", "id", "name", "description", "severity")
    ).lower()
    if any(re.search(pattern, text) for pattern in PLC_FAULT_BUCKET_PATTERNS):
        return PLC_FAULT_BUCKET_HINT
    return PLC_COMPROMISE_BUCKET_HINT


def _hybrid_record_ips(record: dict | None) -> set[str]:
    if not isinstance(record, dict):
        return set()
    return {
        str(ip_text).strip()
        for ip_text in record.get("ip_addresses", []) or []
        if str(ip_text or "").strip() and not _is_oob_management_ip(str(ip_text))
    }


def _node_matches_hybrid_record(node: Node, record: dict | None) -> bool:
    if not record:
        return False
    return bool(_hybrid_record_ips(record).intersection(risk_candidate_node_ips(node, include_oob=False)))


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

    direct_tokens = [
        str(getattr(node, "name", "") or "").strip(),
        str(getattr(node, "hostname", "") or "").strip(),
        *risk_candidate_node_ips(node, include_oob=False),
    ]
    direct_match = _match_risk_node_from_tokens(direct_tokens, risk_nodes)
    if direct_match:
        hybrid_record = _hybrid_record_for_identity(direct_match)
        if not hybrid_record or _node_matches_hybrid_record(node, hybrid_record):
            return direct_match

    hybrid_tokens = [
        str(getattr(node, "name", "") or "").strip(),
        str(getattr(node, "hostname", "") or "").strip(),
        *risk_candidate_node_ips(node, include_oob=True),
    ]
    for token in hybrid_tokens:
        hybrid_record = _hybrid_record_for_identity(token)
        if not hybrid_record or not _node_matches_hybrid_record(node, hybrid_record):
            continue
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
        record_ips = _hybrid_record_ips(hybrid_record)
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


def _merge_vulnerability_rows(vulnerabilities: list[dict]) -> list[dict]:
    def _coerce_float(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    vuln_map = {}
    for vuln in vulnerabilities:
        cve = str(vuln.get("id") or "").strip()
        if not cve:
            continue
        entry = vuln_map.setdefault(
            cve,
            {
                "id": cve,
                "epss": 0.0,
                "cvss": None,
                "severity": "",
                "name": "",
                "description": "",
                "port": "",
                "bucket_hint": "",
                "sources": set(),
            },
        )
        entry["epss"] = max(entry["epss"], float(vuln.get("epss") or 0.0))
        cvss_score = _coerce_float(vuln.get("cvss"))
        if cvss_score is None:
            cvss_score = _coerce_float(vuln.get("cvss_score"))
        if cvss_score is not None:
            if entry["cvss"] is None or cvss_score > float(entry["cvss"]):
                entry["cvss"] = cvss_score
        severity = str(vuln.get("severity") or "").strip()
        if severity and not entry["severity"]:
            entry["severity"] = severity
        name = str(vuln.get("name") or "").strip()
        if name and not entry["name"]:
            entry["name"] = name
        description = str(vuln.get("description") or "").strip()
        if description and len(description) > len(entry["description"]):
            entry["description"] = description
        port = str(vuln.get("port") or "").strip()
        if port and not entry["port"]:
            entry["port"] = port
        bucket_hint = normalize_risk_vulnerability_bucket_hint(
            vuln.get("bucket_hint")
            or vuln.get("bucket")
            or vuln.get("risk_bucket")
            or vuln.get("vulnerability_bucket")
        )
        if bucket_hint and not entry["bucket_hint"]:
            entry["bucket_hint"] = bucket_hint
        source = vuln.get("source")
        if source:
            entry["sources"].add(str(source))

    rows = [
        {
            "id": cve,
            "epss": entry["epss"],
            "cvss": entry["cvss"],
            "severity": entry["severity"],
            "name": entry["name"],
            "description": entry["description"],
            "port": entry["port"],
            "bucket_hint": entry["bucket_hint"],
            "sources": sorted(entry["sources"]),
        }
        for cve, entry in vuln_map.items()
    ]
    rows.sort(key=lambda value: value["epss"], reverse=True)
    return rows


def _mapped_node_rank(node: Node, risk_node_id: str, vulnerability_count: int) -> tuple[int, int, int, int]:
    in_band_ips = set(risk_candidate_node_ips(node, include_oob=False))
    hybrid_matches = len(in_band_ips.intersection(_hybrid_record_ips(_hybrid_record_for_identity(risk_node_id))))
    return (
        hybrid_matches,
        vulnerability_count,
        len(in_band_ips),
        int(getattr(node, "id", 0) or 0),
    )


def build_cyber_data_for_risk_nodes(
    risk_nodes: List[str],
    scan_run_id: int | None = None,
) -> Tuple[Dict, List[Dict]]:
    """Build cyber.json payload and return a node mapping list."""
    scanned_nodes: list[dict] = []
    mapped_nodes: list[dict] = []

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

    def is_mapped(node: Node) -> bool:
        return _resolve_risk_node_id_for_node(node, risk_nodes, mapping_by_node_id, mapping_by_ip) is not None

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

    scan_candidate_ips_by_node_id = {
        node.id: risk_candidate_node_ips(node, include_oob=True)
        for node in selected_nodes
    }
    all_candidate_ips = sorted(
        {
            ip_text
            for ip_values in scan_candidate_ips_by_node_id.values()
            for ip_text in ip_values
        }
    )
    gvmd_findings_by_ip: dict[str, list[dict]] = {}
    if all_candidate_ips:
        try:
            gvmd_findings = fetch_gvmd_findings_for_ips(
                all_candidate_ips,
                limit=max(500, len(all_candidate_ips) * 250),
            )
        except Exception:
            gvmd_findings = []
        for finding in gvmd_findings:
            host_ip = str(finding.get("host_ip") or "").strip()
            if host_ip:
                gvmd_findings_by_ip.setdefault(host_ip, []).append(finding)

    mapped_entries_by_risk_node_id: dict[str, dict] = {}
    mapped_entry_ranks: dict[str, tuple[int, int, int, int]] = {}

    for node in selected_nodes:
        vulnerabilities = []

        # Global vulnerabilities tied to Node
        for vuln in Vulnerability.objects.filter(nodes=node):
            epss = epss_from_cvss(vuln.score, vuln.severity)
            vulnerabilities.append(
                {
                    "id": vuln.cve_id,
                    "epss": epss,
                    "cvss": vuln.score,
                    "severity": vuln.severity,
                    "name": vuln.package or vuln.cve_id,
                    "description": vuln.description,
                    "source": "node",
                }
            )

        # Scan-specific vulnerabilities tied by any known interface IP for the asset.
        scan_candidate_ips = scan_candidate_ips_by_node_id.get(node.id, [])
        if scan_candidate_ips:
            scan_vulns = ScanVulnerability.objects.filter(host_ip__in=scan_candidate_ips)
            if scan_run_id is not None:
                scan_vulns = scan_vulns.filter(scan_run_id=scan_run_id)
            for scan_vuln in scan_vulns:
                epss = epss_from_cvss(scan_vuln.cvss_score, scan_vuln.severity)
                vulnerabilities.append(
                    {
                        "id": scan_vuln.cve_id,
                        "epss": epss,
                        "cvss": scan_vuln.cvss_score,
                        "severity": scan_vuln.severity,
                        "name": scan_vuln.name,
                        "description": scan_vuln.description,
                        "source": "scan",
                    }
                )
            for ip_text in scan_candidate_ips:
                for gvmd_finding in gvmd_findings_by_ip.get(ip_text, []):
                    cve_id = str(gvmd_finding.get("cve_id") or "").strip()
                    if not cve_id:
                        continue
                    vulnerabilities.append(
                        {
                            "id": cve_id,
                            "epss": epss_from_cvss(gvmd_finding.get("cvss_score"), gvmd_finding.get("severity")),
                            "cvss": gvmd_finding.get("cvss_score"),
                            "severity": gvmd_finding.get("severity"),
                            "name": gvmd_finding.get("name"),
                            "description": gvmd_finding.get("description"),
                            "port": gvmd_finding.get("port"),
                            "source": "gvmd",
                        }
                    )

        vuln_list = _merge_vulnerability_rows(vulnerabilities)
        top_vulns = vuln_list[:10]

        node_id = _resolve_risk_node_id_for_node(node, risk_nodes, mapping_by_node_id, mapping_by_ip)
        if not node_id:
            continue

        enriched_top_vulns = []
        for vulnerability in top_vulns:
            enriched_vulnerability = dict(vulnerability)
            bucket_hint = classify_risk_finding_bucket(node_id, enriched_vulnerability, node=node)
            if bucket_hint:
                enriched_vulnerability["bucket_hint"] = bucket_hint
            enriched_top_vulns.append(enriched_vulnerability)

        entry = {
            "node_id": node.id,
            "name": node.name,
            "ip_address": preferred_risk_node_ip(node),
            "risk_node_id": node_id,
            "vulnerability_count": len(vuln_list),
            "vulnerabilities": enriched_top_vulns,
            "has_vulnerabilities": bool(vuln_list),
        }
        rank = _mapped_node_rank(node, node_id, len(vuln_list))
        existing_rank = mapped_entry_ranks.get(node_id)
        if existing_rank is None or rank > existing_rank:
            mapped_entry_ranks[node_id] = rank
            mapped_entries_by_risk_node_id[node_id] = entry

    mapped_nodes = sorted(mapped_entries_by_risk_node_id.values(), key=lambda item: str(item["risk_node_id"]))
    scanned_nodes = [
        {
            "id": item["risk_node_id"],
            "type": "network_node",
            "vulnerability": item["vulnerabilities"],
        }
        for item in mapped_nodes
    ]
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
