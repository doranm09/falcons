from __future__ import annotations

from typing import Any, Dict, Optional

from django.db.models import Q
from django.urls import reverse

from .models import Node, ScanVulnerability, Vulnerability


def resolve_siem_pivot(asset_ip: Optional[str], asset_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not asset_ip and not asset_id:
        return None

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
        return None

    scan_run_id = node.scan_run_id
    scan_url = None
    scan_vuln_count = None
    if scan_run_id:
        scan_url = reverse("dashboard:vuln-detail", args=[scan_run_id])
        scan_vuln_count = ScanVulnerability.objects.filter(
            scan_run_id=scan_run_id,
            host_ip=node.ip_address,
        ).count()

    node_cve_count = Vulnerability.objects.filter(nodes=node).count()

    return {
        "node_id": node.id,
        "node_name": node.name,
        "node_ip": node.ip_address,
        "agent_id": node.agent_id,
        "node_url": reverse("dashboard:node_detail_page", args=[node.id]),
        "scan_run_id": scan_run_id,
        "scan_url": scan_url,
        "scan_vuln_count": scan_vuln_count,
        "node_cve_count": node_cve_count,
    }
