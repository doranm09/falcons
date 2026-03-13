import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard import tasks as dashboard_tasks
from dashboard.models import AgentCommand, Node, ScanRun, ScanVulnerability
from sliver import tasks as sliver_tasks
from sliver.models import (
    AuditLog,
    Engagement,
    ImplantArtifact,
    ImplantTemplate,
    SliverSession,
    TaskTemplate,
    Teamserver,
)


class _FakeNmapProcess:
    def __init__(self):
        self.stdout = iter(
            [
                "Host: 172.30.2.10 ()  Status: Up\n",
                "Host: 172.30.2.11 ()  Status: Up\n",
                "Stats: About 100.00% done; ETC\n",
            ]
        )

    def wait(self):
        return 0


class _FakeSliverRPC:
    def shell(self, session_id, command, timeout=30):
        return json.dumps({"output": f"executed {command}", "error": "", "exit_code": 0})


class _FakeSliverClient:
    def __init__(self):
        self.rpc = _FakeSliverRPC()


@pytest.mark.django_db
def test_ot_campaign_scan_enumerate_vuln_and_sliver_automation(
    user,
    user_client,
    agent_client,
    monkeypatch,
):
    alive_hosts = {"172.30.2.10", "172.30.2.11"}

    def fake_ping(cmd, stdout=None, stderr=None):
        ip = cmd[-1]
        if ip in alive_hosts:
            return SimpleNamespace(returncode=0, stdout=b"time=4.2 ms", stderr=b"")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"host unreachable")

    monkeypatch.setattr(dashboard_tasks.subprocess, "run", fake_ping)
    monkeypatch.setattr(dashboard_tasks, "parse_ping_latency", Mock(return_value=4.2))
    monkeypatch.setattr(dashboard_tasks.scan_network_task, "update_state", Mock())
    monkeypatch.setattr(dashboard_tasks.nmap_discovery_task, "update_state", Mock())

    # 1) Network discovery scan
    scan_summary = dashboard_tasks.scan_network_task("172.30.2.8/29")
    assert "nodes" in scan_summary
    ping_scan = ScanRun.objects.filter(scan_type="ping").latest("timestamp")
    discovered_ips = set(Node.objects.filter(scan_run=ping_scan).values_list("ip_address", flat=True))
    assert discovered_ips == alive_hosts

    # 2) Endpoint enumeration by nmap discovery + agent cyber report (ports)
    monkeypatch.setattr(dashboard_tasks.subprocess, "Popen", lambda *args, **kwargs: _FakeNmapProcess())
    nmap_summary = dashboard_tasks.nmap_discovery_task("172.30.2.8/29")
    assert "hosts discovered" in nmap_summary
    nmap_scan = ScanRun.objects.filter(scan_type="nmap").latest("timestamp")
    nmap_ips = set(Node.objects.filter(scan_run=nmap_scan).values_list("ip_address", flat=True))
    assert {"172.30.2.10", "172.30.2.11"} <= nmap_ips

    report_payload = {
        "agent_id": "agent-l3",
        "hostname": "kali-observed-l3",
        "interfaces": [{"name": "eth0", "ip": "172.30.2.10", "mac": "00:11:22:33:44:55"}],
    }
    report_resp = agent_client.post(
        reverse("dashboard:agent_report"),
        data=json.dumps(report_payload),
        content_type="application/json",
    )
    assert report_resp.status_code == 200

    cyber_payload = {
        "agent_id": "agent-l3",
        "cyber_data": {
            "OS": "Linux",
            "lib": ["openssl", "curl"],
            "MAC": ["00:11:22:33:44:55"],
            "port": [{"id": 22, "state": "LISTEN"}, {"id": 80, "state": "LISTEN"}],
        },
    }
    cyber_resp = agent_client.post(
        reverse("dashboard:agent_cyber_report"),
        data=json.dumps(cyber_payload),
        content_type="application/json",
    )
    assert cyber_resp.status_code == 200
    enumerated_node = Node.objects.get(agent_id="agent-l3")
    assert enumerated_node.active_ports and len(enumerated_node.active_ports) == 2

    # 3) Vulnerability discovery (OpenVAS path, mocked)
    monkeypatch.setattr(dashboard_tasks, "openvas_session", Mock(return_value=object()))
    monkeypatch.setattr(dashboard_tasks, "create_target", Mock(return_value="target-1"))
    monkeypatch.setattr(dashboard_tasks, "start_scan", Mock(return_value="task-1"))
    monkeypatch.setattr(
        dashboard_tasks,
        "get_task_status",
        Mock(return_value={"status": "Done", "report_id": "report-1"}),
    )
    monkeypatch.setattr(dashboard_tasks, "get_report_id", Mock(return_value="report-1"))
    report_xml = """
    <report>
      <results>
        <result>
          <host>172.30.2.10</host>
          <name>Critical Test Finding</name>
          <description>Simulated OpenVAS finding for integration flow.</description>
          <severity>8.1</severity>
          <nvt oid="1.3.6.1.4.1.25623.1.0.900001">
            <name>Simulated NVT</name>
            <cve>CVE-2026-0001</cve>
          </nvt>
        </result>
      </results>
    </report>
    """
    monkeypatch.setattr(dashboard_tasks, "download_report", Mock(return_value=report_xml))

    dashboard_tasks.launch_openvas_scan_task("172.30.2.0/24")
    dashboard_tasks.poll_openvas_results()

    assert ScanVulnerability.objects.filter(
        host_ip="172.30.2.10",
        cve_id="CVE-2026-0001",
    ).exists()

    # 4) Automated penetration-test action via Sliver task + deploy to host agent
    teamserver = Teamserver.objects.create(name="ts-campaign", host="127.0.0.1", port=31337)
    engagement = Engagement.objects.create(
        name="eng-campaign",
        teamserver=teamserver,
        operator=user,
        status=Engagement.Status.ACTIVE,
        target_scope="172.30.2.0/24",
    )
    session = SliverSession.objects.create(
        session_id="sess-campaign-1",
        name="campaign-beacon",
        engagement=engagement,
        status=SliverSession.Status.ACTIVE,
        last_checkin=timezone.now(),
        remote_address="172.30.2.10",
    )
    template = TaskTemplate.objects.create(
        name="campaign-whoami",
        command="whoami",
        category="recon",
    )

    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=_FakeSliverClient()))
    task_result = sliver_tasks.execute_sliver_command_task(
        session_id=session.session_id,
        command=template.command,
        user_id=user.id,
        template_id=template.id,
    )
    assert task_result["status"] == "COMPLETED"

    implant_template = ImplantTemplate.objects.create(
        name="campaign-linux-x64",
        config={"format": "elf"},
        file_format="elf",
        operating_system="linux",
        architecture="amd64",
    )
    artifact = ImplantArtifact.objects.create(
        name="campaign-implant",
        file_name="campaign-implant.elf",
        engagement=engagement,
        template=implant_template,
        generated_by=user,
        status=ImplantArtifact.Status.READY,
        sha256="deadc0de",
        file_size=1337,
    )

    deploy_resp = user_client.post(
        reverse("sliver:deploy_implant_to_agent", args=[artifact.id]),
        {"agent_id": "agent-l3", "execute_after": "on"},
    )
    assert deploy_resp.status_code == 302

    queued_command = AgentCommand.objects.get(agent_id="agent-l3", action="sliver_deploy")
    poll_resp = agent_client.get(reverse("dashboard:agent_commands") + "?agent_id=agent-l3")
    assert poll_resp.status_code == 200
    command_ids = {item["id"] for item in poll_resp.json().get("commands", [])}
    assert queued_command.id in command_ids

    result_resp = agent_client.post(
        reverse("dashboard:agent_command_result"),
        data=json.dumps(
            {
                "agent_id": "agent-l3",
                "command_id": queued_command.id,
                "output": "sliver_deploy saved to /tmp/campaign-implant.elf (executed pid=4242)",
            }
        ),
        content_type="application/json",
    )
    assert result_resp.status_code == 200
    assert AuditLog.objects.filter(
        action=AuditLog.Action.IMPLANT_EXECUTED,
        engagement=engagement,
    ).exists()
