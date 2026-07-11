from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _post_json(url: str, payload: object, token: str) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-SIEM-Token": token,
        },
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        response.read()


def _read_runtime_metadata(runtime_dir: Path) -> dict[str, dict]:
    metadata = {}
    for path in runtime_dir.glob("*.json"):
        try:
            metadata[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
    return metadata


def _load_state(state_path: Path) -> dict:
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_state(state_path: Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state), encoding="utf-8")


def _expand_patterns(directory: Path, patterns: list[str]) -> list[Path]:
    matched = []
    seen = set()
    for pattern in patterns:
        for path in sorted(directory.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                matched.append(path)
    return matched


def _collect_new_lines(directory: Path, patterns: list[str], state: dict, batch_size: int) -> list[dict]:
    events = []
    for path in _expand_patterns(directory, patterns):
        offset = int(state.get(str(path), 0))
        with path.open("r", encoding="utf-8") as handle:
            handle.seek(offset)
            while len(events) < batch_size:
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        stem = path.stem
                        event.setdefault("log_type", stem)
                        event.setdefault("_log_path", str(path))
                    events.append(event)
                except json.JSONDecodeError:
                    continue
            state[str(path)] = handle.tell()
        if len(events) >= batch_size:
            break
    return events


def main() -> None:
    base_url = os.getenv("SIEM_SERVER_URL", "http://host.docker.internal:8000/dashboard")
    token = (
        os.getenv("SIEM_SENSOR_TOKEN")
        or os.getenv("SIEM_INGEST_TOKEN")
        or os.getenv("AGENT_API_TOKEN", "")
    )
    runtime_dir = Path(os.getenv("SIEM_RUNTIME_DIR", "/var/lib/siem/runtime"))
    suricata_dir = Path(os.getenv("SIEM_SURICATA_DIR", "/var/lib/siem/suricata"))
    zeek_dir = Path(os.getenv("SIEM_ZEEK_DIR", "/var/lib/siem/zeek"))
    suricata_patterns = [item.strip() for item in os.getenv("SIEM_SURICATA_PATTERNS", "eve.json,eve.jsonl").split(",") if item.strip()]
    zeek_patterns = [item.strip() for item in os.getenv("SIEM_ZEEK_PATTERNS", "current/*.log,*.jsonl").split(",") if item.strip()]
    state_path = Path(os.getenv("SIEM_FORWARDER_STATE", "/var/lib/siem/state/offsets.json"))
    poll_interval = float(os.getenv("SIEM_FORWARDER_POLL_SEC", "10"))
    heartbeat_interval = float(os.getenv("SIEM_SENSOR_HEARTBEAT_SEC", "30"))
    batch_size = int(os.getenv("SIEM_SENSOR_BATCH_SIZE", "200"))

    state = _load_state(state_path)
    last_heartbeat = {}
    while True:
        runtime = _read_runtime_metadata(runtime_dir)
        now = time.time()

        for sensor_id, sensor_meta in runtime.items():
            sensor_type = "suricata" if "suricata" in sensor_id else "zeek"
            if now - float(last_heartbeat.get(sensor_id, 0)) >= heartbeat_interval:
                envelope = {"sensor": sensor_meta, "events": []} if sensor_type == "suricata" else {"sensor": sensor_meta, "logs": []}
                try:
                    endpoint = f"{base_url}/siem/sensors/{sensor_type}/{'eve' if sensor_type == 'suricata' else 'logs'}/"
                    _post_json(endpoint, envelope, token)
                    last_heartbeat[sensor_id] = now
                except (HTTPError, URLError):
                    pass

        suricata_events = _collect_new_lines(suricata_dir, suricata_patterns, state, batch_size)
        if suricata_events:
            sensor_meta = runtime.get("suricata-sensor", {"sensor_id": "suricata-sensor"})
            try:
                _post_json(
                    f"{base_url}/siem/sensors/suricata/eve/",
                    {"sensor": sensor_meta, "events": suricata_events},
                    token,
                )
            except (HTTPError, URLError):
                pass

        zeek_logs = _collect_new_lines(zeek_dir, zeek_patterns, state, batch_size)
        if zeek_logs:
            sensor_meta = runtime.get("zeek-sensor", {"sensor_id": "zeek-sensor"})
            try:
                _post_json(
                    f"{base_url}/siem/sensors/zeek/logs/",
                    {"sensor": sensor_meta, "logs": zeek_logs},
                    token,
                )
            except (HTTPError, URLError):
                pass

        _save_state(state_path, state)
        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
