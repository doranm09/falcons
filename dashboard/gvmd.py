from __future__ import annotations

import logging
from collections.abc import Iterable

from django.db import connections


logger = logging.getLogger(__name__)


def _severity_label(score) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "None"
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0:
        return "Low"
    return "None"


def _split_cves(cve_text: str, fallback_oid: str) -> list[str]:
    raw = str(cve_text or "").strip()
    if raw:
        values = []
        for token in raw.replace(";", ",").replace("\n", ",").split(","):
            normalized = token.strip()
            if normalized:
                values.append(normalized[:32])
        if values:
            return values
    return [fallback_oid[:32] if fallback_oid else "NVT"]


def fetch_gvmd_findings_for_ips(asset_ips: Iterable[str], limit: int = 200) -> list[dict]:
    cleaned_ips = sorted({str(ip).strip() for ip in asset_ips if str(ip).strip()})
    if not cleaned_ips:
        return []

    sql = """
        SELECT
            r.host,
            r.port,
            r.severity,
            r.description,
            rp.uuid AS report_uuid,
            t.uuid AS task_uuid,
            t.name AS task_name,
            COALESCE(n.oid, rn.nvt, r.nvt) AS nvt_oid,
            COALESCE(n.name, r.nvt, 'OpenVAS finding') AS nvt_name,
            n.cve AS nvt_cves,
            n.summary AS nvt_summary
        FROM results r
        LEFT JOIN result_nvts rn ON rn.id = r.result_nvt
        LEFT JOIN nvts n ON n.oid = COALESCE(rn.nvt, r.nvt)
        LEFT JOIN reports rp ON rp.id = r.report
        LEFT JOIN tasks t ON t.id = r.task
        WHERE r.host = ANY(%s)
          AND COALESCE(r.severity, 0) > 0
        ORDER BY COALESCE(r.severity, 0) DESC, rp.end_time DESC NULLS LAST, r.id DESC
        LIMIT %s
    """

    try:
        with connections["gvmd"].cursor() as cursor:
            cursor.execute(sql, [cleaned_ips, int(limit)])
            rows = cursor.fetchall()
    except Exception as exc:
        logger.warning("GVMD findings lookup failed for %s: %s", cleaned_ips, exc)
        return []

    findings = []
    seen = set()
    for host, port, severity, description, report_uuid, task_uuid, task_name, nvt_oid, nvt_name, nvt_cves, nvt_summary in rows:
        host_ip = str(host or "").strip()
        for cve_id in _split_cves(nvt_cves, str(nvt_oid or "")):
            key = (host_ip, cve_id, str(report_uuid or ""), str(nvt_oid or ""))
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "host_ip": host_ip,
                    "port": str(port or ""),
                    "cve_id": cve_id,
                    "name": str(nvt_name or cve_id),
                    "severity": _severity_label(severity),
                    "cvss_score": float(severity) if severity is not None else None,
                    "description": str(description or nvt_summary or ""),
                    "report_uuid": str(report_uuid or ""),
                    "task_uuid": str(task_uuid or ""),
                    "task_name": str(task_name or ""),
                    "nvt_oid": str(nvt_oid or ""),
                    "source_type": "GVMD",
                    "link_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if str(cve_id).startswith("CVE-") else "",
                }
            )
    return findings
