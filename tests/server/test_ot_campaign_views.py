from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.urls import reverse

from dashboard.models import CampaignRun, ScanRun


@pytest.mark.django_db
def test_start_ot_campaign_returns_task_id(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_task = SimpleNamespace(id="campaign-task-123")
    delay_mock = Mock(return_value=mock_task)
    monkeypatch.setattr(dashboard_views.run_ot_campaign_task, "delay", delay_mock)

    response = user_client.post(
        reverse("dashboard:start-ot-campaign"),
        {
            "cidr": "172.30.2.0/24",
            "scan_method": "nmap",
            "run_openvas": "on",
            "sliver_command": "whoami",
            "collect_loot": "on",
        },
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["task_id"] == "campaign-task-123"
    assert "campaign_run_id" in payload
    assert payload["scan_method"] == "nmap"
    assert delay_mock.call_args.kwargs["run_openvas"] is True
    assert delay_mock.call_args.kwargs["campaign_run_id"] == payload["campaign_run_id"]


@pytest.mark.django_db
def test_start_ot_campaign_rejects_invalid_cidr(user_client):
    response = user_client.post(
        reverse("dashboard:start-ot-campaign"),
        {"cidr": "not-a-cidr"},
    )
    assert response.status_code == 400
    assert "invalid CIDR" in response.json()["error"]


@pytest.mark.django_db
def test_start_ot_campaign_accepts_openvas_false(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_task = SimpleNamespace(id="campaign-task-openvas-off")
    delay_mock = Mock(return_value=mock_task)
    monkeypatch.setattr(dashboard_views.run_ot_campaign_task, "delay", delay_mock)

    response = user_client.post(
        reverse("dashboard:start-ot-campaign"),
        {"cidr": "172.30.2.0/24", "run_openvas": "0"},
    )
    assert response.status_code == 202
    assert delay_mock.call_args.kwargs["run_openvas"] is False


@pytest.mark.django_db
def test_start_ot_campaign_creates_campaign_run(user_client, user, monkeypatch):
    from dashboard import views as dashboard_views

    mock_task = SimpleNamespace(id="campaign-task-create-model")
    delay_mock = Mock(return_value=mock_task)
    monkeypatch.setattr(dashboard_views.run_ot_campaign_task, "delay", delay_mock)

    response = user_client.post(
        reverse("dashboard:start-ot-campaign"),
        {
            "cidr": "172.30.2.0/24",
            "scan_method": "ping",
            "run_openvas": "1",
            "collect_loot": "0",
            "sliver_command": "id",
        },
    )
    assert response.status_code == 202
    payload = response.json()

    run = CampaignRun.objects.get(id=payload["campaign_run_id"])
    assert run.requested_by == user
    assert run.cidr == "172.30.2.0/24"
    assert run.scan_method == "ping"
    assert run.run_openvas is True
    assert run.collect_loot is False
    assert run.sliver_command == "id"
    assert run.celery_task_id == "campaign-task-create-model"
    assert run.status == CampaignRun.Status.RUNNING


@pytest.mark.django_db
def test_ot_campaign_status_returns_progress(monkeypatch, user_client):
    from dashboard import views as dashboard_views

    fake_result = SimpleNamespace(
        state="PROGRESS",
        info={"step": "openvas", "message": "OpenVAS state: Running", "steps_completed": 2, "total_steps": 4},
        ready=lambda: False,
        result=None,
    )
    monkeypatch.setattr(dashboard_views, "AsyncResult", Mock(return_value=fake_result))

    response = user_client.get(reverse("dashboard:ot-campaign-status", args=["task-1"]))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "PROGRESS"
    assert payload["step"] == "openvas"


@pytest.mark.django_db
def test_ot_campaign_status_returns_result(monkeypatch, user_client):
    from dashboard import views as dashboard_views

    fake_result = SimpleNamespace(
        state="SUCCESS",
        info={},
        ready=lambda: True,
        result={"status": "completed", "errors": []},
    )
    monkeypatch.setattr(dashboard_views, "AsyncResult", Mock(return_value=fake_result))

    response = user_client.get(reverse("dashboard:ot-campaign-status", args=["task-2"]))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "SUCCESS"
    assert payload["result"]["status"] == "completed"


@pytest.mark.django_db
def test_ot_campaign_history_returns_report_link(user_client):
    openvas_scan = ScanRun.objects.create(cidr="172.30.2.0/24", status="COMPLETE", scan_type="openvas")
    run = CampaignRun.objects.create(
        cidr="172.30.2.0/24",
        scan_method="nmap",
        status=CampaignRun.Status.COMPLETED,
        duration_seconds=42,
        discovered_hosts_count=2,
        vulnerability_count=3,
        error_count=1,
        error_details="openvas: simulated error",
        openvas_scan=openvas_scan,
    )

    response = user_client.get(reverse("dashboard:ot-campaign-history"))
    assert response.status_code == 200
    payload = response.json()
    assert payload["history"]

    item = payload["history"][0]
    assert item["id"] == run.id
    assert item["duration_seconds"] == 42
    assert item["vulnerability_count"] == 3
    assert item["error_count"] == 1
    assert item["report_url"] == reverse("dashboard:vuln-detail", args=[openvas_scan.id])
