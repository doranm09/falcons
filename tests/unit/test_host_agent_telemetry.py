import json
from pathlib import Path

from host_agent.telemetry import (
    build_fim_baseline,
    diff_fim,
    build_fim_events,
    build_osquery_event,
    hash_file,
)


def test_hash_file(tmp_path: Path):
    path = tmp_path / "file.txt"
    path.write_text("hello")
    digest = hash_file(str(path))
    assert len(digest) == 64


def test_build_fim_events(tmp_path: Path):
    path = tmp_path / "file.txt"
    path.write_text("hello")
    baseline = build_fim_baseline([str(path)])
    path.write_text("hello2")
    current = build_fim_baseline([str(path)])
    changes = diff_fim(baseline, current)
    events = build_fim_events(changes, "agent-1", "host")
    assert events[0]["event_type"] == "fim.change"


def test_build_osquery_event():
    event = build_osquery_event("select 1;", [{"x": 1}], "agent-1", "host")
    assert event["event_type"] == "osquery.result"
