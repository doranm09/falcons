from __future__ import annotations

from typing import Any, Dict

from django.utils import timezone

from .models import Alert, Case


def build_case_from_alert(alert: Alert) -> Case:
    title_parts = [alert.rule_name]
    if alert.asset_ip:
        title_parts.append(alert.asset_ip)
    elif alert.asset_id:
        title_parts.append(alert.asset_id)
    title = " - ".join(title_parts)
    description = f"Alert: {alert.summary}\nEvent Type: {alert.event_type}\nSource: {alert.source}"
    case = Case(
        title=title,
        description=description,
        priority=Case.Priority.MEDIUM,
        status=Case.Status.OPEN,
    )
    return case


def export_case_payload(case: Case) -> Dict[str, Any]:
    return {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "priority": case.priority,
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "alerts": [
            {
                "id": alert.id,
                "rule_name": alert.rule_name,
                "rule_type": alert.rule_type,
                "event_type": alert.event_type,
                "source": alert.source,
                "severity": alert.severity,
                "asset_ip": alert.asset_ip,
                "asset_id": alert.asset_id,
                "summary": alert.summary,
                "count": alert.count,
                "first_seen": alert.first_seen.isoformat(),
                "last_seen": alert.last_seen.isoformat(),
            }
            for alert in case.alerts.all()
        ],
        "notes": [
            {
                "id": note.id,
                "author": note.author.username if note.author else None,
                "note": note.note,
                "created_at": note.created_at.isoformat(),
            }
            for note in case.notes.all()
        ],
        "evidence": [
            {
                "id": item.id,
                "label": item.label,
                "evidence_type": item.evidence_type,
                "details": item.details,
                "created_at": item.created_at.isoformat(),
            }
            for item in case.evidence.all()
        ],
    }
