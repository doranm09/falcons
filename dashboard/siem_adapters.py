from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime

from django.utils import timezone

from .models import AgentStatus, Node, ScanRun, SbomReport, Vulnerability


SEVERITY_MAP = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "low": 3,
    "none": 0,
}


def _ensure_dt(value: Optional[datetime]) -> datetime:
    ts = value or timezone.now()
    if timezone.is_naive(ts):
        ts = timezone.make_aware(ts, timezone=timezone.utc)
    return ts


def _isoformat(value: Optional[datetime]) -> str:
    return _ensure_dt(value).isoformat()


def _severity_from_score(score: Optional[float], severity_label: str = "") -> Optional[int]:
    if score is not None:
        try:
            return max(0, min(10, int(round(score))))
        except (TypeError, ValueError):
            return None
    if severity_label:
        return SEVERITY_MAP.get(severity_label.strip().lower())
    return None


def _base_event(
    *,
    event_type: str,
    source: str,
    timestamp: Optional[datetime],
    summary: str = "",
    severity: Optional[int] = None,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "@timestamp": _isoformat(timestamp),
        "event_type": event_type,
        "source": source,
        "message": summary,
        "event": {
            "kind": "event",
        },
    }
    if severity is not None:
        event["event"]["severity"] = severity
    return event


def _attach_host(event: Dict[str, Any], host: Dict[str, Any]) -> None:
    if host:
        event["host"] = {k: v for k, v in host.items() if v not in (None, "")}


def _attach_agent(event: Dict[str, Any], agent: Dict[str, Any]) -> None:
    if agent:
        event["agent"] = {k: v for k, v in agent.items() if v not in (None, "")}


def adapt_agent_status(agent: AgentStatus) -> Dict[str, Any]:
    event = _base_event(
        event_type="agent.heartbeat",
        source="agent",
        timestamp=agent.last_heartbeat,
        summary=f"Agent heartbeat: {agent.hostname}",
    )
    event["event"].update(
        {
            "category": ["host"],
            "type": ["info"],
            "action": "heartbeat",
            "outcome": "success" if agent.status == "online" else "unknown",
        }
    )
    _attach_host(
        event,
        {
            "hostname": agent.hostname,
            "ip": [agent.ip_address],
            "os": {
                "type": agent.os_type,
                "version": agent.os_version,
                "platform": agent.platform,
            },
        },
    )
    _attach_agent(
        event,
        {
            "id": agent.agent_id,
            "name": agent.hostname,
            "version": agent.agent_version,
        },
    )
    event["labels"] = {
        "status": agent.status,
        "cpu_count": agent.cpu_count,
        "memory_total": agent.memory_total,
    }
    return event


def adapt_scan_run(scan: ScanRun) -> Dict[str, Any]:
    event_type = "scan.run"
    outcome = "unknown"
    if scan.status in ("COMPLETE", "COMPLETED"):
        outcome = "success"
    elif scan.status == "FAILED":
        outcome = "failure"

    event = _base_event(
        event_type=event_type,
        source="scanner",
        timestamp=scan.timestamp,
        summary=f"{scan.scan_type} scan on {scan.cidr}",
    )
    event["event"].update(
        {
            "category": ["scan"],
            "type": ["start" if scan.status in ("PENDING", "RUNNING") else "end"],
            "action": scan.scan_type,
            "outcome": outcome,
        }
    )
    event["labels"] = {
        "scan_id": scan.id,
        "cidr": scan.cidr,
        "scan_status": scan.status,
    }
    return event


def adapt_vulnerability(vuln: Vulnerability, node: Optional[Node] = None) -> Dict[str, Any]:
    severity = _severity_from_score(vuln.score, vuln.severity)
    summary = f"{vuln.cve_id} detected"
    if node:
        summary += f" on {node.ip_address}"

    event = _base_event(
        event_type="vulnerability.detected",
        source="vulnerability",
        timestamp=vuln.last_modified,
        summary=summary,
        severity=severity,
    )
    event["event"].update(
        {
            "category": ["vulnerability"],
            "type": ["info"],
            "action": "detected",
            "outcome": "success",
        }
    )
    event["rule"] = {
        "id": vuln.cve_id,
        "name": vuln.description[:120],
        "reference": vuln.references,
        "category": "cve",
    }
    event["vulnerability"] = {
        "id": vuln.cve_id,
        "severity": vuln.severity,
        "score": vuln.score,
    }
    if node:
        _attach_host(
            event,
            {
                "hostname": node.name,
                "ip": [node.ip_address],
                "id": node.agent_id or str(node.id),
            },
        )
    return event


def adapt_sbom_report(report: SbomReport) -> Dict[str, Any]:
    summary = f"SBOM report from {report.agent_id}"
    event = _base_event(
        event_type="sbom.report",
        source="sbom",
        timestamp=report.created_at,
        summary=summary,
    )
    event["event"].update(
        {
            "category": ["package"],
            "type": ["info"],
            "action": "sbom_report",
            "outcome": "success",
        }
    )
    event["labels"] = {
        "package_count": report.package_count,
        "format": report.format,
        "bom_format": report.bom_format,
        "spec_version": report.spec_version,
        "sha256": report.sha256,
    }
    if report.node:
        _attach_host(
            event,
            {
                "hostname": report.node.name,
                "ip": [report.node.ip_address],
                "id": report.node.agent_id or str(report.node.id),
            },
        )
    _attach_agent(
        event,
        {
            "id": report.agent_id,
        },
    )
    return event
