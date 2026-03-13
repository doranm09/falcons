import base64
import json
import pytest
from unittest.mock import Mock
from django.utils import timezone

from sliver import tasks as sliver_tasks
from sliver.models import (
    Teamserver,
    Engagement,
    SliverSession,
    TaskTemplate,
    ImplantTemplate,
    ImplantArtifact,
    Loot,
    SliverEvent,
    Watcher,
)


class FakeSliverRPC:
    def __init__(self):
        self._sessions = [
            {
                "ID": "sess-1",
                "Name": "alpha",
                "Hostname": "host1",
                "Username": "user1",
                "OS": "linux",
                "Arch": "amd64",
                "IsDead": False,
                "IsBeacon": True,
                "ReconnectIntervalSeconds": 60,
                "RemoteAddress": "10.0.0.5",
                "Version": "1.0",
            }
        ]
        self._loot = []
        self._generate_payload = None

    def sessions(self):
        return json.dumps({"sessions": self._sessions})

    def shell(self, session_id, command, timeout=30):
        return json.dumps({"output": f"ran {command}", "error": "", "exit_code": 0})

    def task(self, session_id, command, args, timeout=60):
        return json.dumps({"output": "ok", "error": "", "exit_code": 0})

    def generate(self, name, config):
        payload = self._generate_payload or base64.b64encode(b"default-implant").decode()
        return json.dumps({"data": payload})

    def loot(self):
        return json.dumps({"loot": self._loot})


class FakeSliverClient:
    def __init__(self, rpc=None):
        self.rpc = rpc or FakeSliverRPC()


@pytest.fixture
def sliver_task_setup(user):
    teamserver = Teamserver.objects.create(name="ts1", host="127.0.0.1", port=31337)
    engagement = Engagement.objects.create(
        name="eng1",
        teamserver=teamserver,
        operator=user,
        status=Engagement.Status.ACTIVE,
    )
    session = SliverSession.objects.create(
        session_id="sess-1",
        engagement=engagement,
        status=SliverSession.Status.ACTIVE,
        last_checkin=timezone.now(),
    )
    template = TaskTemplate.objects.create(
        name="whoami",
        command="whoami",
        category="recon",
    )
    return {
        "teamserver": teamserver,
        "engagement": engagement,
        "session": session,
        "template": template,
    }


@pytest.mark.django_db
def test_sync_sessions_task_creates_sessions(monkeypatch, sliver_task_setup, user):
    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient()))

    result = sliver_tasks.sync_sessions_task(engagement_id=sliver_task_setup["engagement"].id, user_id=user.id)
    assert "synced_sessions" in result
    assert SliverSession.objects.filter(session_id="sess-1").exists()


@pytest.mark.django_db
def test_sync_sessions_task_allows_none_user(monkeypatch, sliver_task_setup):
    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient()))

    result = sliver_tasks.sync_sessions_task(
        engagement_id=sliver_task_setup["engagement"].id,
        user_id=None,
    )
    assert "synced_sessions" in result
    assert SliverSession.objects.filter(session_id="sess-1").exists()


@pytest.mark.django_db
def test_execute_sliver_command_task_updates_job(monkeypatch, sliver_task_setup, user):
    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient()))

    result = sliver_tasks.execute_sliver_command_task(
        session_id=sliver_task_setup["session"].session_id,
        command="whoami",
        user_id=user.id,
        template_id=sliver_task_setup["template"].id,
    )

    assert result["status"] in ["COMPLETED", "FAILED"]
    assert result["job_id"].startswith("job_")


@pytest.mark.django_db
def test_generate_implant_task_creates_file(monkeypatch, sliver_task_setup, user, tmp_path):
    rpc = FakeSliverRPC()
    rpc._generate_payload = base64.b64encode(b"implant-bytes").decode()

    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient(rpc)))
    monkeypatch.setattr(sliver_tasks, "get_artifact_base_dir", Mock(return_value=tmp_path))

    template = ImplantTemplate.objects.create(
        name="win-x64",
        config={"format": "exe"},
        file_format="exe",
        operating_system="windows",
        architecture="amd64",
    )
    artifact = ImplantArtifact.objects.create(
        name="artifact-1",
        file_name="artifact-1.exe",
        engagement=sliver_task_setup["engagement"],
        template=template,
        generated_by=user,
        status=ImplantArtifact.Status.PENDING,
    )

    result = sliver_tasks.generate_implant_task(
        engagement_id=sliver_task_setup["engagement"].id,
        template_id=template.id,
        name="artifact-1",
        user_id=user.id,
        artifact_id=artifact.id,
    )

    artifact.refresh_from_db()
    assert artifact.status == ImplantArtifact.Status.READY
    assert artifact.relative_path
    assert (tmp_path / artifact.relative_path).is_file()
    assert result["status"] == ImplantArtifact.Status.READY


@pytest.mark.django_db
def test_collect_loot_task_saves_file(monkeypatch, sliver_task_setup, user, settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path
    rpc = FakeSliverRPC()
    rpc._loot = [
        {
            "LootID": "loot-1",
            "Name": "secrets.txt",
            "Type": "FILE",
            "SessionID": sliver_task_setup["session"].session_id,
            "Data": base64.b64encode(b"loot-data").decode(),
            "Size": 9,
        }
    ]

    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient(rpc)))

    result = sliver_tasks.collect_loot_task(
        session_id=sliver_task_setup["session"].session_id,
        user_id=user.id,
    )

    loot = Loot.objects.get(loot_id="loot-1")
    assert loot.local_path
    assert loot.local_path.path
    assert loot.local_path.storage.exists(loot.local_path.name)
    assert result["collected_loot"] == 1


@pytest.mark.django_db
def test_collect_loot_task_allows_none_user(monkeypatch, sliver_task_setup, settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path
    rpc = FakeSliverRPC()
    rpc._loot = [
        {
            "LootID": "loot-none-user",
            "Name": "ops.txt",
            "Type": "FILE",
            "SessionID": sliver_task_setup["session"].session_id,
            "Data": base64.b64encode(b"ops-data").decode(),
            "Size": 8,
        }
    ]

    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient(rpc)))

    result = sliver_tasks.collect_loot_task(
        session_id=sliver_task_setup["session"].session_id,
        user_id=None,
    )

    loot = Loot.objects.get(loot_id="loot-none-user")
    assert loot.operator is None
    assert result["collected_loot"] == 1


@pytest.mark.django_db
def test_trigger_watcher_response_collect_loot_uses_system_user(monkeypatch, sliver_task_setup):
    event = SliverEvent.objects.create(
        event_id="event-collect-1",
        event_type=SliverEvent.Type.SESSION_OPENED,
        teamserver=sliver_task_setup["teamserver"],
        engagement=sliver_task_setup["engagement"],
        session=sliver_task_setup["session"],
        data={"EventID": "event-collect-1"},
        message="session opened",
    )
    watcher = Watcher.objects.create(
        name="collect-loot-watcher",
        engagement=sliver_task_setup["engagement"],
        event_filter={"EventType": "SESSION_OPENED"},
        action_config={"actions": [{"type": "collect_loot"}]},
        is_active=True,
    )

    delay_mock = Mock()
    monkeypatch.setattr(sliver_tasks.collect_loot_task, "delay", delay_mock)

    sliver_tasks.trigger_watcher_response(watcher_id=watcher.id, event_id=event.event_id)
    delay_mock.assert_called_once_with(
        session_id=sliver_task_setup["session"].session_id,
        user_id=None,
    )


@pytest.mark.django_db
def test_sync_loot_task_queues_session_sync_with_none_user(monkeypatch, sliver_task_setup):
    rpc = FakeSliverRPC()
    rpc._loot = [
        {
            "LootID": "loot-sync-1",
            "Name": "sync.txt",
            "Type": "FILE",
            "SessionID": sliver_task_setup["session"].session_id,
            "Data": "sync-data",
            "Size": 9,
        }
    ]

    delay_mock = Mock()
    monkeypatch.setattr(sliver_tasks, "sliver_client", object())
    monkeypatch.setattr(sliver_tasks, "get_sliver_client", Mock(return_value=FakeSliverClient(rpc)))
    monkeypatch.setattr(sliver_tasks.sync_sessions_task, "delay", delay_mock)

    result = sliver_tasks.sync_loot_task(engagement_id=sliver_task_setup["engagement"].id)
    delay_mock.assert_called_once_with(sliver_task_setup["engagement"].id, None)
    assert result["total_loot_synced"] == 1
    assert Loot.objects.filter(loot_id="loot-sync-1").exists()
