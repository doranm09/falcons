from __future__ import annotations

from typing import Dict, Optional

from django.db.models import Q

from .models import Alert, Node, ScanVulnerability, Vulnerability


def resolve_asset_context(event: Dict) -> Dict[str, Optional[int]]:
    asset_ip = event.get("asset_ip")
    asset_id = event.get("asset_id")

    if not asset_ip and not asset_id:
        return {"node_id": None, "scan_run_id": None, "scan_vuln_count": None, "node_cve_count": None}

    query = Q()
    if asset_ip:
        query |= Q(ip_address=asset_ip)
    if asset_id:
        query |= Q(agent_id=asset_id)

    node = (
        Node.objects.filter(query)
        .select_related("scan_run")
        .order_by("-scan_run__timestamp", "-id")
        .first()
    )

    if not node:
        return {"node_id": None, "scan_run_id": None, "scan_vuln_count": None, "node_cve_count": None}

    scan_run_id = node.scan_run_id
    scan_vuln_count = None
    if scan_run_id and node.ip_address:
        scan_vuln_count = ScanVulnerability.objects.filter(
            scan_run_id=scan_run_id,
            host_ip=node.ip_address,
        ).count()

    node_cve_count = Vulnerability.objects.filter(nodes=node).count()

    return {
        "node_id": node.id,
        "scan_run_id": scan_run_id,
        "scan_vuln_count": scan_vuln_count,
        "node_cve_count": node_cve_count,
    }


def enrich_alert(alert: Alert, event: Dict) -> None:
    context = resolve_asset_context(event)
    if context.get("scan_vuln_count") is not None:
        alert.summary = f"{alert.summary} [scan_vulns:{context['scan_vuln_count']}]"
    if context.get("node_cve_count") is not None:
        alert.summary = f"{alert.summary} [node_cves:{context['node_cve_count']}]"
    alert.save(update_fields=["summary"])
