#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE_FILE = ROOT / "docker-compose-hybrid.yml"
DEFAULT_BASE_URL = "http://127.0.0.1:8000/dashboard"


def run(argv: list[str]) -> None:
    subprocess.run(argv, cwd=str(ROOT), check=True, text=True)


def run_python(script: Path, args: list[str]) -> None:
    run([sys.executable, str(script), *args])


def fetch_json(url: str, timeout_sec: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_sec) as response:
        return json.load(response)


def explorer_url(base_url: str, **params: str) -> str:
    query = urllib.parse.urlencode({key: value for key, value in params.items() if value})
    return f"{base_url.rstrip('/')}/siem/events/explorer/{'?' + query if query else ''}"


def summarize_sensor_status(base_url: str) -> dict:
    payload = fetch_json(f"{base_url.rstrip('/')}/siem/sensors/health/")
    sensors = payload.get("sensors", [])
    summary = {
        "total": len(sensors),
        "online": 0,
        "stale": 0,
        "error": 0,
        "by_sensor": {},
    }
    for sensor in sensors:
        status = str(sensor.get("status") or "unknown")
        if status == "online":
            summary["online"] += 1
        elif status == "stale":
            summary["stale"] += 1
        else:
            summary["error"] += 1
        summary["by_sensor"][str(sensor.get("sensor_id") or status)] = {
            "status": status,
            "event_count": int(sensor.get("event_count", 0) or 0),
            "interfaces": list(sensor.get("interfaces") or []),
        }
    return summary


def summarize_ids_events(base_url: str) -> dict:
    ids = fetch_json(
        f"{base_url.rstrip('/')}/siem/events/?"
        + urllib.parse.urlencode(
            {
                "event_module_in": "suricata,zeek",
                "exclude_stats": "1",
                "limit": "5",
            }
        )
    )
    suricata_alerts = fetch_json(
        f"{base_url.rstrip('/')}/siem/events/?"
        + urllib.parse.urlencode(
            {
                "event_dataset": "suricata.alert",
                "exclude_stats": "1",
                "limit": "5",
            }
        )
    )
    zeek = fetch_json(
        f"{base_url.rstrip('/')}/siem/events/?"
        + urllib.parse.urlencode(
            {
                "event_module": "zeek",
                "exclude_stats": "1",
                "limit": "5",
            }
        )
    )
    hybrid = fetch_json(
        f"{base_url.rstrip('/')}/siem/events/?"
        + urllib.parse.urlencode(
            {
                "event_dataset": "agent.network_connection",
                "exclude_stats": "1",
                "limit": "5",
            }
        )
    )
    return {
        "ids_events": int(ids.get("count", 0) or 0),
        "suricata_alerts": int(suricata_alerts.get("count", 0) or 0),
        "zeek_events": int(zeek.get("count", 0) or 0),
        "hybrid_connection_events": int(hybrid.get("count", 0) or 0),
        "sample_ids_events": ids.get("results", [])[:3],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Drive hybrid traffic, verify live SIEM sensors, and print a concise Network IDS demo walkthrough."
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
        help="Timeout passed to the runtime and sensor verification helpers",
    )
    parser.add_argument(
        "--traffic-iterations",
        type=int,
        default=2,
        help="How many intentional traffic rounds to drive before checking the live feed",
    )
    parser.add_argument(
        "--min-zeek-events",
        type=int,
        default=1,
        help="Minimum Zeek event count required in the sensor health endpoint",
    )
    parser.add_argument(
        "--skip-runtime",
        action="store_true",
        help="Skip the hybrid traffic-driving verification step",
    )
    parser.add_argument(
        "--skip-sensors",
        action="store_true",
        help="Skip the SIEM sensor pipeline verification step",
    )
    args = parser.parse_args()

    compose_file = str(Path(args.compose_file).resolve())
    scripts_dir = Path(__file__).resolve().parent

    if not args.skip_runtime:
        run_python(
            scripts_dir / "verify_hybrid_runtime.py",
            [
                "--compose-file",
                compose_file,
                "--timeout-sec",
                str(args.timeout_sec),
                "--traffic-iterations",
                str(args.traffic_iterations),
            ],
        )

    if not args.skip_sensors:
        run_python(
            scripts_dir / "verify_siem_sensors.py",
            [
                "--compose-file",
                compose_file,
                "--base-url",
                args.base_url,
                "--timeout-sec",
                str(args.timeout_sec),
                "--min-zeek-events",
                str(args.min_zeek_events),
            ],
        )

    sensor_summary = summarize_sensor_status(args.base_url)
    event_summary = summarize_ids_events(args.base_url)

    urls = {
        "live_monitor": f"{args.base_url.rstrip('/')}/siem/",
        "sensor_health": f"{args.base_url.rstrip('/')}/siem/sensors/health/view/",
        "suricata_alerts": explorer_url(
            args.base_url,
            event_dataset="suricata.alert",
            exclude_stats="1",
        ),
        "zeek_protocols": explorer_url(
            args.base_url,
            event_module="zeek",
            event_dataset="zeek.conn,zeek.dns,zeek.http,zeek.ssl,zeek.notice,zeek.files",
            exclude_stats="1",
        ),
        "hybrid_connections": explorer_url(
            args.base_url,
            event_dataset="agent.network_connection,zeek.conn,suricata.flow",
            exclude_stats="1",
        ),
        "agent_topology": f"{args.base_url.rstrip('/')}/network/monitoring/",
    }

    summary = {
        "sensor_summary": sensor_summary,
        "event_summary": event_summary,
        "urls": urls,
    }

    print("Live IDS demo is ready")
    print(json.dumps(summary, indent=2, sort_keys=True))
    print()
    print("Suggested walkthrough:")
    print(f"1. Open Live Monitor: {urls['live_monitor']}")
    print("2. Point out online sensors, Suricata alert volume, Zeek activity, and the recent live feed rows.")
    print(f"3. Open Suricata Alerts preset: {urls['suricata_alerts']}")
    print("4. Open Zeek Protocols preset and call out conn/dns/http/tls activity from the hybrid stack.")
    print(f"5. Open Sensor Health: {urls['sensor_health']}")
    print("6. Open Hybrid Connections preset to show agent connection telemetry beside the IDS feed.")
    print(f"7. Open agent topology view: {urls['agent_topology']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
