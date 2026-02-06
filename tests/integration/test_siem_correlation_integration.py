import json

import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import Alert, AlertRule, Node, ScanRun, ScanVulnerability, Vulnerability


@pytest.mark.django_db
def test_pipeline_ingest_adds_correlation_tags(client):
    scan_run = ScanRun.objects.create(cidr="10.0.0.0/24")
    node = Node.objects.create(
        scan_run=scan_run,
        ip_address="10.0.0.10",
        name="node-10",
        agent_id="agent-10",
    )
    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.10",
        cve_id="CVE-2024-0301",
        name="HTTP Vuln",
    )
    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-0302",
        description="Test vuln",
        severity="Medium",
        score=5.0,
        published=timezone.now(),
        last_modified=timezone.now(),
    )
    vuln.nodes.add(node)

    AlertRule.objects.create(
        name="Pipeline Correlation Rule",
        rule_type="sigma",
        enabled=True,
        match_event_type="zeek.conn",
        match_contains="pipeline",
        suppression_minutes=0,
    )

    payload = {
        "uid": "C3",
        "id_orig_h": "10.0.0.10",
        "ts": 1760088060,
        "message": "pipeline conn",
    }
    ingest_resp = client.post(
        reverse("dashboard:siem_pipeline_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201
    assert Alert.objects.count() == 1
    alert = Alert.objects.first()
    assert alert is not None
    assert "pipeline conn" in alert.summary
    assert "[scan_vulns:1]" in alert.summary
    assert "[node_cves:1]" in alert.summary
