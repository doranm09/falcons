import json

import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import Alert, AlertRule, Node, ScanRun, ScanVulnerability, Vulnerability


@pytest.mark.django_db
def test_siem_alert_includes_correlation_tags(client):
    scan_run = ScanRun.objects.create(cidr="10.0.0.0/24")
    node = Node.objects.create(
        scan_run=scan_run,
        ip_address="10.0.0.9",
        name="node-9",
        agent_id="agent-9",
    )
    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.9",
        cve_id="CVE-2024-0201",
        name="SSH Vuln",
    )
    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-0202",
        description="Test vuln",
        severity="High",
        score=7.5,
        published=timezone.now(),
        last_modified=timezone.now(),
    )
    vuln.nodes.add(node)

    AlertRule.objects.create(
        name="Correlation Rule",
        rule_type="sigma",
        enabled=True,
        match_event_type="zeek.conn",
        match_source="zeek",
        match_contains="conn",
        suppression_minutes=0,
    )

    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:20:00Z",
        "message": "conn observed",
        "asset_ip": "10.0.0.9",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert Alert.objects.count() == 1
    alert = Alert.objects.first()
    assert alert is not None
    assert "conn observed" in alert.summary
    assert "[scan_vulns:1]" in alert.summary
    assert "[node_cves:1]" in alert.summary
