from types import SimpleNamespace

import pytest

from dashboard import tasks as dashboard_tasks
from dashboard.models import CampaignRun, Node, ScanRun


class _FakeNmapProcess:
    def __init__(self):
        self.stdout = iter(
            [
                "Host: 172.30.2.10 ()  Status: Up\n",
                "Stats: About 34.00% done; ETC\n",
                "Host: 172.30.2.11 ()  Status: Up\n",
                "Stats: About 100.00% done; ETC\n",
            ]
        )

    def wait(self):
        return 0


@pytest.mark.django_db
def test_nmap_discovery_task_reports_progress_callback(monkeypatch):
    progress_events = []
    monkeypatch.setattr(dashboard_tasks.subprocess, "Popen", lambda *args, **kwargs: _FakeNmapProcess())

    summary = dashboard_tasks.nmap_discovery_task(
        "172.30.2.8/29",
        progress_callback=lambda meta: progress_events.append(meta),
    )

    assert "hosts discovered" in summary
    assert progress_events
    assert any(event.get("percent") == 0 for event in progress_events)
    assert any(event.get("percent") == 100 for event in progress_events)
    assert any(event.get("hosts_found", 0) >= 2 for event in progress_events)

    scan = ScanRun.objects.filter(scan_type="nmap").latest("timestamp")
    discovered = set(Node.objects.filter(scan_run=scan).values_list("ip_address", flat=True))
    assert {"172.30.2.10", "172.30.2.11"} <= discovered


@pytest.mark.django_db
def test_run_ot_campaign_task_persists_discovery_log_lines(monkeypatch):
    alive_hosts = {"172.30.2.1", "172.30.2.2"}

    def fake_ping(cmd, stdout=None, stderr=None):
        ip = cmd[-1]
        if ip in alive_hosts:
            return SimpleNamespace(returncode=0, stdout=b"time=2.1 ms", stderr=b"")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"timeout")

    monkeypatch.setattr(dashboard_tasks.subprocess, "run", fake_ping)
    monkeypatch.setattr(dashboard_tasks, "parse_ping_latency", lambda output: 2.1)

    run = CampaignRun.objects.create(
        cidr="172.30.2.0/30",
        scan_method="ping",
        run_openvas=False,
        collect_loot=False,
        status=CampaignRun.Status.PENDING,
    )

    result = dashboard_tasks.run_ot_campaign_task(
        cidr="172.30.2.0/30",
        scan_method="ping",
        run_openvas=False,
        collect_loot=False,
        campaign_run_id=run.id,
    )

    run.refresh_from_db()
    payload = run.result_payload or {}
    log_lines = payload.get("log_lines") or []

    assert run.status == CampaignRun.Status.COMPLETED
    assert result["status"] == "completed"
    assert log_lines
    assert any("[discovery]" in line for line in log_lines)
    assert any("Discovery completed" in line for line in log_lines)
