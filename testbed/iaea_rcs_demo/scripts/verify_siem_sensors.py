#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE_FILE = ROOT / "docker-compose-hybrid.yml"
DEFAULT_BASE_URL = "http://127.0.0.1:8000/dashboard"


def run(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=str(cwd or ROOT),
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def docker_compose(compose_file: Path, args: list[str]) -> str:
    return run(["docker", "compose", "-f", str(compose_file), *args], cwd=ROOT)


def load_compose_ps(compose_file: Path) -> list[dict]:
    output = docker_compose(compose_file, ["ps", "--format", "json"]).strip()
    if not output:
        return []
    try:
        rows = json.loads(output)
        if isinstance(rows, list):
            return rows
    except json.JSONDecodeError:
        pass
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def wait_for_running_services(compose_file: Path, expected_services: set[str], timeout_sec: int) -> None:
    deadline = time.time() + timeout_sec
    last_seen: list[dict] = []
    while time.time() < deadline:
        rows = load_compose_ps(compose_file)
        last_seen = rows
        by_service = {row.get("Service") or row.get("service"): row for row in rows}
        missing = sorted(expected_services - set(by_service))
        not_running = []
        for service in expected_services & set(by_service):
            row = by_service[service]
            state = str(row.get("State") or row.get("Status") or "").lower()
            if "running" not in state:
                not_running.append(f"{service}={state or 'unknown'}")
        if not missing and not not_running:
            return
        time.sleep(2)
    raise SystemExit(
        "services did not reach running state: "
        + json.dumps({"last_seen": last_seen}, indent=2)
    )


def docker_exec(container_name: str, argv: list[str]) -> str:
    return run(["docker", "exec", container_name, *argv])


def fetch_json(url: str, timeout_sec: int) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_sec) as response:
        return json.load(response)


def read_forwarder_offsets() -> dict[str, int]:
    output = docker_exec(
        "siem-forwarder",
        ["sh", "-lc", "cat /var/lib/siem/state/offsets.json 2>/dev/null || printf '{}'"],
    )
    try:
        data = json.loads(output.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid forwarder offsets JSON: {exc}")
    if not isinstance(data, dict):
        raise SystemExit("forwarder offsets payload is not an object")
    return {str(key): int(value) for key, value in data.items()}


def read_zeek_file_stats() -> dict[str, int]:
    snippet = r"""
import json
from pathlib import Path

targets = [
    Path("/var/lib/siem/zeek/spool/logger/conn.log"),
    Path("/var/lib/siem/zeek/spool/logger/notice.log"),
    Path("/var/lib/siem/zeek/current/conn.log"),
]
stats = {}
for path in targets:
    if path.exists():
        stats[str(path)] = path.stat().st_size
print(json.dumps(stats, sort_keys=True))
"""
    output = docker_exec("zeek-sensor", ["python3", "-c", snippet])
    data = json.loads(output)
    return {str(key): int(value) for key, value in data.items()}


def sensor_map(payload: dict) -> dict[str, dict]:
    sensors = payload.get("sensors", [])
    result: dict[str, dict] = {}
    for sensor in sensors:
        if isinstance(sensor, dict) and sensor.get("sensor_id"):
            result[str(sensor["sensor_id"])] = sensor
    return result


def verify_siem_runtime(base_url: str, timeout_sec: int, min_zeek_events: int) -> dict:
    deadline = time.time() + timeout_sec
    last_state: dict[str, object] = {"error": "verification not started"}
    while time.time() < deadline:
        try:
            health = fetch_json(f"{base_url.rstrip('/')}/siem/sensors/health/", timeout_sec=5)
            sensors = sensor_map(health)
            zeek = sensors.get("zeek-sensor", {})
            suricata = sensors.get("suricata-sensor", {})
            offsets = read_forwarder_offsets()
            zeek_stats = read_zeek_file_stats()

            zeek_offset = offsets.get("/var/lib/siem/zeek/spool/logger/conn.log", 0)
            zeek_status_ok = zeek.get("status") == "online"
            zeek_events_ok = int(zeek.get("event_count", 0) or 0) >= min_zeek_events
            suricata_status_ok = suricata.get("status") == "online"
            zeek_log_ok = any(
                path.startswith("/var/lib/siem/zeek/") and size > 0
                for path, size in zeek_stats.items()
            )

            if zeek_status_ok and zeek_events_ok and suricata_status_ok and zeek_offset > 0 and zeek_log_ok:
                return {
                    "health": health,
                    "forwarder_offsets": offsets,
                    "zeek_files": zeek_stats,
                }

            last_state = {
                "health": health,
                "forwarder_offsets": offsets,
                "zeek_files": zeek_stats,
                "checks": {
                    "zeek_online": zeek_status_ok,
                    "zeek_event_count": int(zeek.get("event_count", 0) or 0),
                    "suricata_online": suricata_status_ok,
                    "zeek_offset": zeek_offset,
                    "zeek_log_ok": zeek_log_ok,
                },
            }
        except Exception as exc:
            last_state = {"error": str(exc)}
        time.sleep(2)
    raise SystemExit("SIEM sensor verification timed out: " + json.dumps(last_state, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the hybrid Zeek/Suricata sensor pipeline through the dashboard health endpoint"
    )
    parser.add_argument(
        "--compose-file",
        default=str(DEFAULT_COMPOSE_FILE),
        help=f"Compose file to verify (default: {DEFAULT_COMPOSE_FILE})",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Dashboard base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=90,
        help="How long to wait for services and SIEM health to converge",
    )
    parser.add_argument(
        "--min-zeek-events",
        type=int,
        default=1,
        help="Minimum Zeek event_count required in the health endpoint",
    )
    args = parser.parse_args()

    compose_file = Path(args.compose_file).resolve()
    wait_for_running_services(compose_file, {"zeek-sensor", "suricata-sensor", "siem-forwarder"}, args.timeout_sec)
    result = verify_siem_runtime(args.base_url, args.timeout_sec, args.min_zeek_events)

    print("SIEM sensor verification passed")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
