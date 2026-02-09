from __future__ import annotations

from typing import Any, Dict

import requests
from django.db import connections
from django.utils import timezone

from .models import Alert, Case, Hunt, SiemEvent
from .opensearch_client import _get_config


def _check_database() -> Dict[str, Any]:
    try:
        with connections["default"].cursor() as cursor:
            cursor.execute("SELECT 1")
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _check_opensearch() -> Dict[str, Any]:
    config = _get_config()
    if not config:
        return {"status": "disabled"}
    try:
        auth = (config.username, config.password) if config.username else None
        resp = requests.get(
            f"{config.url}",
            auth=auth,
            verify=config.verify_tls,
            timeout=3,
        )
        return {"status": "ok" if resp.ok else "error", "code": resp.status_code}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def health_snapshot() -> Dict[str, Any]:
    checks = {
        "database": _check_database(),
        "opensearch": _check_opensearch(),
    }
    overall = "ok"
    for check in checks.values():
        if check["status"] == "error":
            overall = "degraded"
            break
    return {
        "status": overall,
        "timestamp": timezone.now().isoformat(),
        "checks": checks,
    }


def metrics_payload() -> str:
    snapshot = health_snapshot()
    checks = snapshot.get("checks", {})

    lines = [
        "# HELP cybertwin_service_up Service health (1=up, 0=down, -1=disabled)",
        "# TYPE cybertwin_service_up gauge",
    ]
    for name, check in checks.items():
        status = check.get("status")
        value = 1
        if status == "error":
            value = 0
        elif status == "disabled":
            value = -1
        lines.append(f"cybertwin_service_up{{service=\"{name}\"}} {value}")

    lines.extend(
        [
            "# HELP cybertwin_siem_events_total Total SIEM events",
            "# TYPE cybertwin_siem_events_total gauge",
            f"cybertwin_siem_events_total {SiemEvent.objects.count()}",
            "# HELP cybertwin_siem_alerts_open Open SIEM alerts",
            "# TYPE cybertwin_siem_alerts_open gauge",
            f"cybertwin_siem_alerts_open {Alert.objects.filter(status=Alert.Status.OPEN).count()}",
            "# HELP cybertwin_siem_cases_open Open SIEM cases",
            "# TYPE cybertwin_siem_cases_open gauge",
            f"cybertwin_siem_cases_open {Case.objects.filter(status=Case.Status.OPEN).count()}",
            "# HELP cybertwin_siem_hunts_open Open SIEM hunts",
            "# TYPE cybertwin_siem_hunts_open gauge",
            f"cybertwin_siem_hunts_open {Hunt.objects.filter(status=Hunt.Status.OPEN).count()}",
        ]
    )

    return "\n".join(lines) + "\n"
