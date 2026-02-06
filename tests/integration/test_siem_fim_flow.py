import json
from pathlib import Path

import pytest
from django.urls import reverse

from host_agent.telemetry import build_fim_baseline, diff_fim, build_fim_events


@pytest.mark.django_db
def test_fim_events_ingest_and_search(siem_client, tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello")
    baseline = build_fim_baseline([str(file_path)])
    file_path.write_text("hello2")
    current = build_fim_baseline([str(file_path)])
    changes = diff_fim(baseline, current)
    events = build_fim_events(changes, "agent-1", "host")

    resp = siem_client.post(
        reverse("dashboard:siem_pipeline_ingest"),
        data=json.dumps(events),
        content_type="application/json",
    )
    assert resp.status_code == 201

    search_resp = siem_client.get(reverse("dashboard:siem_event_search"), {"event_type": "fim.change"})
    assert search_resp.status_code == 200
    body = search_resp.json()
    assert body["count"] == 1
