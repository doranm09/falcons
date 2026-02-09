from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List

from django.utils import timezone

from .models import Alert, AlertRule
from .siem_correlation import resolve_asset_context


def _alert_summary(event: Dict[str, Any]) -> str:
    summary = event.get("summary") or ""
    matches = event.get("ioc_matches") or []
    if matches:
        tags = ", ".join({m.get("value") for m in matches if m.get("value")})
        if tags:
            summary = f"{summary} [IOC: {tags}]".strip()
    return summary


def _alert_raw_sample(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("raw") or {}
    if not isinstance(raw, dict):
        raw = {"raw": raw}
    if event.get("ioc_matches"):
        raw = {**raw, "ioc_matches": event.get("ioc_matches")}
    return raw


def should_trigger(rule: AlertRule, event: Dict[str, Any]) -> bool:
    if not rule.enabled:
        return False
    if rule.match_event_type and event.get("event_type") != rule.match_event_type:
        return False
    if rule.match_source and event.get("source") != rule.match_source:
        return False
    if rule.rule_type == AlertRule.RuleType.SURICATA and not str(event.get("event_type", "")).startswith("suricata"):
        return False

    contains = rule.match_contains.strip()
    if contains:
        summary = str(event.get("summary") or "").lower()
        raw = str(event.get("raw") or "").lower()
        if contains.lower() not in summary and contains.lower() not in raw:
            return False
    return True


def build_dedup_key(rule: AlertRule, event: Dict[str, Any]) -> str:
    asset_ip = event.get("asset_ip") or "-"
    asset_id = event.get("asset_id") or "-"
    return f"{rule.id}:{event.get('event_type')}:{asset_ip}:{asset_id}"


def create_or_update_alert(rule: AlertRule, event: Dict[str, Any]) -> Alert:
    dedup_key = build_dedup_key(rule, event)
    now = timezone.now()
    suppression = timedelta(minutes=rule.suppression_minutes or 0)

    existing = (
        Alert.objects.filter(
            dedup_key=dedup_key,
            status=Alert.Status.OPEN,
        )
        .order_by("-last_seen")
        .first()
    )

    if existing and (now - existing.last_seen) <= suppression:
        existing.count += 1
        existing.last_seen = now
        existing.summary = event.get("summary") or existing.summary
        existing.raw_sample = event.get("raw") or existing.raw_sample
        existing.save(update_fields=["count", "last_seen", "summary", "raw_sample"])
        return existing

    context = resolve_asset_context(event)
    summary = _alert_summary(event)
    if context.get("scan_vuln_count") is not None:
        summary = f"{summary} [scan_vulns:{context['scan_vuln_count']}]"
    if context.get("node_cve_count") is not None:
        summary = f"{summary} [node_cves:{context['node_cve_count']}]"

    alert = Alert.objects.create(
        rule=rule,
        rule_name=rule.name,
        rule_type=rule.rule_type,
        event_type=event.get("event_type") or "",
        source=event.get("source") or "",
        severity=rule.severity if rule.severity is not None else event.get("severity"),
        asset_ip=event.get("asset_ip"),
        asset_id=event.get("asset_id"),
        summary=summary,
        status=Alert.Status.OPEN,
        dedup_key=dedup_key,
        raw_sample=_alert_raw_sample(event),
    )
    return alert


def process_alerts_for_events(events: List[Dict[str, Any]]) -> List[Alert]:
    rules = list(AlertRule.objects.filter(enabled=True))
    alerts: List[Alert] = []
    for event in events:
        for rule in rules:
            if should_trigger(rule, event):
                alerts.append(create_or_update_alert(rule, event))
    return alerts
