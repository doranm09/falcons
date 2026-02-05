import pytest
import secrets
from unittest.mock import Mock
from django.core.files.base import ContentFile
from django.contrib.messages import get_messages
from django.urls import reverse
from django.utils import timezone

from dashboard.models import AgentStatus, AgentCommand
from sliver.models import (
    Teamserver, Engagement, SliverSession, SliverJob, TaskTemplate, Loot,
    ImplantTemplate, ImplantArtifact,
)


@pytest.fixture
def sliver_objects(user):
    teamserver = Teamserver.objects.create(
        name="ts1",
        host="127.0.0.1",
        port=31337,
    )
    engagement = Engagement.objects.create(
        name="eng1",
        teamserver=teamserver,
        operator=user,
        status=Engagement.Status.ACTIVE,
        target_scope="192.168.1.0/24",
    )
    session = SliverSession.objects.create(
        session_id="sess-1",
        name="alpha",
        engagement=engagement,
        status=SliverSession.Status.ACTIVE,
        last_checkin=timezone.now(),
        remote_address="192.168.1.10",
    )
    template = TaskTemplate.objects.create(
        name="whoami",
        command="whoami",
        category="recon",
    )
    job = SliverJob.objects.create(
        job_id="job-1",
        session=session,
        status=SliverJob.Status.COMPLETED,
        command="whoami",
        started_at=timezone.now(),
        completed_at=timezone.now(),
    )
    loot = Loot.objects.create(
        loot_id="loot-1",
        name="hosts.txt",
        loot_type=Loot.Type.FILE,
        session=session,
        engagement=engagement,
        operator=user,
    )
    return {
        "teamserver": teamserver,
        "engagement": engagement,
        "session": session,
        "template": template,
        "job": job,
        "loot": loot,
    }


@pytest.fixture
def implant_template():
    return ImplantTemplate.objects.create(
        name="win-x64",
        description="Windows implant",
        config={"format": "exe"},
        file_format="exe",
        operating_system="windows",
        architecture="amd64",
    )


@pytest.fixture
def ready_artifact(sliver_objects, implant_template, settings, tmp_path):
    settings.SLIVER_ARTIFACT_DIR = str(tmp_path)
    file_path = tmp_path / "artifact.exe"
    file_path.write_bytes(b"implant-bytes")
    return ImplantArtifact.objects.create(
        name="artifact-1",
        file_name="artifact.exe",
        relative_path="artifact.exe",
        engagement=sliver_objects["engagement"],
        template=implant_template,
        generated_by=sliver_objects["engagement"].operator,
        status=ImplantArtifact.Status.READY,
        file_size=file_path.stat().st_size,
        sha256="deadbeef",
    )


@pytest.mark.django_db
def test_sliver_dashboard_access(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)

    response = user_client.get(reverse("sliver:dashboard"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_engagement_list_access(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:engagement_list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_engagement_detail_access(user_client, sliver_objects):
    engagement = sliver_objects["engagement"]
    response = user_client.get(reverse("sliver:engagement_detail", args=[engagement.id]))
    assert response.status_code == 200


@pytest.mark.django_db
def test_start_stop_engagement(user_client, sliver_objects):
    engagement = sliver_objects["engagement"]
    engagement.status = Engagement.Status.COMPLETED
    engagement.save(update_fields=["status"])

    response = user_client.post(reverse("sliver:start_engagement", args=[engagement.id]))
    assert response.status_code == 302
    engagement.refresh_from_db()
    assert engagement.status == Engagement.Status.ACTIVE

    response = user_client.post(reverse("sliver:stop_engagement", args=[engagement.id]))
    assert response.status_code == 302
    engagement.refresh_from_db()
    assert engagement.status == Engagement.Status.COMPLETED


@pytest.mark.django_db
def test_session_list_access(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:session_list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_session_detail_access(user_client, sliver_objects):
    session = sliver_objects["session"]
    response = user_client.get(reverse("sliver:session_detail", args=[session.session_id]))
    assert response.status_code == 200


@pytest.mark.django_db
def test_execute_command_creates_job(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    from sliver import tasks as sliver_tasks
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)
    monkeypatch.setattr(sliver_views, "get_sliver_client", Mock(return_value=object()))

    mock_task = Mock()
    mock_task.id = "task-123"
    monkeypatch.setattr(sliver_tasks.execute_sliver_command_task, "delay", Mock(return_value=mock_task))

    session = sliver_objects["session"]
    response = user_client.post(
        reverse("sliver:execute_command", args=[session.session_id]),
        {"command": "whoami"},
    )
    assert response.status_code == 302
    assert SliverJob.objects.filter(job_id="job_task-123").exists()
    messages = [str(m) for m in get_messages(response.wsgi_request)]
    assert any("View job" in message for message in messages)


@pytest.mark.django_db
def test_run_template_creates_job(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    from sliver import tasks as sliver_tasks
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)

    mock_task = Mock()
    mock_task.id = "task-456"
    monkeypatch.setattr(sliver_tasks.execute_sliver_command_task, "delay", Mock(return_value=mock_task))

    session = sliver_objects["session"]
    template = sliver_objects["template"]
    response = user_client.post(
        reverse("sliver:run_template_task", args=[session.session_id]),
        {"template_id": template.id},
    )
    assert response.status_code == 302
    assert SliverJob.objects.filter(job_id="job_task-456").exists()
    messages = [str(m) for m in get_messages(response.wsgi_request)]
    assert any("View job" in message for message in messages)


@pytest.mark.django_db
def test_collect_loot_triggers_task(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    from sliver import tasks as sliver_tasks
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)
    monkeypatch.setattr(sliver_tasks.collect_loot_task, "delay", Mock())

    session = sliver_objects["session"]
    response = user_client.post(reverse("sliver:collect_loot", args=[session.session_id]))
    assert response.status_code == 302


@pytest.mark.django_db
def test_job_list_access(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:job_list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_job_detail_access(user_client, sliver_objects):
    job = sliver_objects["job"]
    response = user_client.get(reverse("sliver:job_detail", args=[job.job_id]))
    assert response.status_code == 200
    assert job.job_id.encode() in response.content


@pytest.mark.django_db
def test_retry_job_creates_new_job(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    from sliver import tasks as sliver_tasks
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)

    mock_task = Mock()
    mock_task.id = "task-retry"
    monkeypatch.setattr(sliver_tasks.execute_sliver_command_task, "delay", Mock(return_value=mock_task))

    job = sliver_objects["job"]
    response = user_client.post(reverse("sliver:retry_job", args=[job.job_id]))
    assert response.status_code == 302
    assert SliverJob.objects.filter(job_id="job_task-retry").exists()


@pytest.mark.django_db
def test_export_jobs_csv(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:job_export"))
    assert response.status_code == 200
    assert response["Content-Type"] == "text/csv"
    assert sliver_objects["job"].job_id.encode() in response.content


@pytest.mark.django_db
def test_job_output_and_error_endpoints(user_client, sliver_objects):
    job = sliver_objects["job"]
    job.output = "output text"
    job.error = "error text"
    job.save(update_fields=["output", "error"])

    response = user_client.get(reverse("sliver:job_output", args=[job.job_id]))
    assert response.status_code == 200
    assert b"output text" in response.content

    response = user_client.get(reverse("sliver:job_error", args=[job.job_id]))
    assert response.status_code == 200
    assert b"error text" in response.content


@pytest.mark.django_db
def test_loot_list_access(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:loot_list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_teamserver_list_access(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)

    response = user_client.get(reverse("sliver:teamserver_list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_teamserver_connection_test(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)
    monkeypatch.setattr(sliver_views, "get_sliver_client", Mock(return_value=object()))

    teamserver = sliver_objects["teamserver"]
    response = user_client.post(reverse("sliver:test_teamserver_connection", args=[teamserver.id]))
    assert response.status_code == 302


@pytest.mark.django_db
def test_teamserver_test_all(user_client, monkeypatch, sliver_objects):
    from sliver import views as sliver_views
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)
    monkeypatch.setattr(sliver_views, "get_sliver_client", Mock(return_value=object()))

    response = user_client.post(reverse("sliver:test_all_teamservers"))
    assert response.status_code == 302


@pytest.mark.django_db
def test_teamserver_create(user_client):
    response = user_client.get(reverse("sliver:teamserver_create"))
    assert response.status_code == 200

    response = user_client.post(reverse("sliver:teamserver_create"), {
        "name": "ts-new",
        "host": "10.0.0.10",
        "port": 31337,
    })
    assert response.status_code == 302
    assert Teamserver.objects.filter(name="ts-new").exists()


@pytest.mark.django_db
def test_teamserver_edit(user_client, sliver_objects):
    teamserver = sliver_objects["teamserver"]
    response = user_client.post(reverse("sliver:teamserver_edit", args=[teamserver.id]), {
        "name": "ts-updated",
        "host": teamserver.host,
        "port": teamserver.port,
    })
    assert response.status_code == 302
    teamserver.refresh_from_db()
    assert teamserver.name == "ts-updated"


@pytest.mark.django_db
def test_teamserver_delete(user_client, sliver_objects):
    teamserver = sliver_objects["teamserver"]
    response = user_client.post(reverse("sliver:teamserver_delete", args=[teamserver.id]))
    assert response.status_code == 302
    assert not Teamserver.objects.filter(id=teamserver.id).exists()


@pytest.mark.django_db
def test_teamserver_form_validation_requires_key_pair(user_client):
    response = user_client.post(reverse("sliver:teamserver_create"), {
        "name": "ts-invalid",
        "host": "10.0.0.20",
        "port": 31337,
        "certificate": "cert-only",
    })
    assert response.status_code == 200
    assert Teamserver.objects.filter(name="ts-invalid").exists() is False


@pytest.mark.django_db
def test_api_sessions_returns_fields(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:api_sessions"))
    assert response.status_code == 200
    payload = response.json()
    assert "sessions" in payload
    assert payload["sessions"][0]["session_id"] == sliver_objects["session"].session_id
    assert "engagement_id" in payload["sessions"][0]
    assert "is_privileged" in payload["sessions"][0]


@pytest.mark.django_db
def test_api_jobs_filters(user_client, sliver_objects):
    job = sliver_objects["job"]
    response = user_client.get(reverse("sliver:api_jobs") + f"?status={job.status}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["jobs"][0]["job_id"] == job.job_id


@pytest.mark.django_db
def test_api_loot_returns_download_url(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:api_loot"))
    assert response.status_code == 200
    payload = response.json()
    assert payload["loot"][0]["loot_id"] == sliver_objects["loot"].loot_id
    assert payload["loot"][0]["download_url"]


@pytest.mark.django_db
def test_task_templates_access(user_client, sliver_objects):
    response = user_client.get(reverse("sliver:task_templates"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_generate_implant_get(user_client, sliver_objects, implant_template):
    response = user_client.get(reverse("sliver:generate_implant"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_generate_implant_post_creates_artifact(user_client, monkeypatch, sliver_objects, implant_template):
    from sliver import views as sliver_views
    from sliver import tasks as sliver_tasks
    monkeypatch.setattr(sliver_views, "SLIVER_AVAILABLE", True)

    mock_task = Mock()
    mock_task.id = "task-999"
    monkeypatch.setattr(sliver_tasks.generate_implant_task, "delay", Mock(return_value=mock_task))

    engagement = sliver_objects["engagement"]
    response = user_client.post(
        reverse("sliver:generate_implant"),
        {"template_id": implant_template.id, "engagement_id": engagement.id, "name": "alpha"},
    )
    assert response.status_code == 302
    artifact = ImplantArtifact.objects.get(name="alpha")
    assert artifact.file_name == "alpha.exe"


@pytest.mark.django_db
def test_implant_artifacts_access(user_client, ready_artifact):
    response = user_client.get(reverse("sliver:implant_artifacts"))
    assert response.status_code == 200
    assert ready_artifact.name.encode() in response.content


@pytest.mark.django_db
def test_download_implant(user_client, ready_artifact):
    response = user_client.get(reverse("sliver:download_implant", args=[ready_artifact.id]))
    assert response.status_code == 200
    content = b"".join(response.streaming_content)
    assert b"implant-bytes" in content


@pytest.mark.django_db
def test_download_implant_token(client, ready_artifact):
    ready_artifact.download_token = "token-123"
    ready_artifact.token_expires_at = timezone.now() + timezone.timedelta(hours=1)
    ready_artifact.save(update_fields=["download_token", "token_expires_at"])

    response = client.get(
        reverse("sliver:download_implant_token", args=[ready_artifact.id]) + "?token=token-123"
    )
    assert response.status_code == 200
    content = b"".join(response.streaming_content)
    assert b"implant-bytes" in content


@pytest.mark.django_db
def test_deploy_implant_to_agent_creates_command(user_client, monkeypatch, sliver_objects, ready_artifact):
    AgentStatus.objects.create(
        agent_id="agent-1",
        hostname="host-1",
        ip_address="10.0.0.10",
    )
    monkeypatch.setattr(secrets, "token_urlsafe", Mock(return_value="token-abc"))

    response = user_client.post(
        reverse("sliver:deploy_implant_to_agent", args=[ready_artifact.id]),
        {"agent_id": "agent-1", "execute_after": "on", "execute_args": "[\"--flag\"]"},
    )
    assert response.status_code == 302
    ready_artifact.refresh_from_db()
    assert ready_artifact.download_token == "token-abc"

    command = AgentCommand.objects.get(agent_id="agent-1", action="sliver_deploy")
    assert command.parameters["execute"] is True
    assert command.parameters["execute_args"] == ["--flag"]


@pytest.mark.django_db
def test_download_loot(user_client, sliver_objects, settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path
    loot = sliver_objects["loot"]
    loot.local_path.save("loot.txt", ContentFile(b"loot-data"))

    response = user_client.get(reverse("sliver:download_loot", args=[loot.id]))
    assert response.status_code == 200
    content = b"".join(response.streaming_content)
    assert b"loot-data" in content
