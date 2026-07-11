#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE_FILE = ROOT / "docker-compose-hybrid.yml"

POINT_TOLERANCE = 8

OPC_TARGETS = {
    "main": ("opc.tcp://10.1.1.14:4840/main", "urn:iaea-rcs-demo:main"),
    "backup": ("opc.tcp://10.1.2.15:4840/backup", "urn:iaea-rcs-demo:backup"),
}

FIELD_PATHS = {
    "main": [
        ("pt455_pv", "plc-main", "10.1.1.9", 1),
        ("pt456_pv", "plc-main", "10.1.1.8", 1),
        ("pt457_pv", "plc-main", "10.1.1.12", 3),
    ],
    "backup": [
        ("pt456_pv", "plc-backup", "10.1.2.8", 1),
        ("pt457_pv", "plc-backup", "10.1.2.12", 3),
        ("pt458_pv", "plc-backup", "10.1.2.13", 4),
    ],
}

HMI_POINT_KEYS = {
    "plc-main": ["pt455_pv", "pt456_pv", "pt457_pv"],
    "plc-backup": ["pt456_pv", "pt457_pv", "pt458_pv"],
}

CORE_REQUIRED_SERVICES = {
    "channel-a",
    "channel-b",
    "channel-c",
    "channel-d",
    "engineer-ws",
    "firewall-0",
    "firewall-1",
    "firewall-2",
    "historian",
    "hmi",
    "metasploit",
    "plc-backup",
    "plc-main",
    "postgres",
    "pt-455",
    "pt-456",
}

LAYER_TRAFFIC_PATHS = [
    ("L4", "metasploit", "10.3.50.10", 443, "Enterprise to historian HTTP/status"),
    ("L4", "metasploit", "10.3.50.10", 4840, "Enterprise to historian north-south path"),
    ("L4", "metasploit", "10.4.50.20", 5432, "Enterprise to postgres"),
    ("L3", "historian", "10.4.50.20", 5432, "Historian to postgres"),
    ("L3", "historian", "10.1.1.14", 4840, "Historian to PLC main OPC"),
    ("L3", "historian", "10.1.2.15", 4840, "Historian to PLC backup OPC"),
    ("L2", "engineer-ws", "10.3.50.10", 443, "Engineering workstation to historian HTTP/status"),
    ("L2", "engineer-ws", "10.3.50.10", 4840, "Engineering workstation to historian OPC/status"),
    ("L2", "engineer-ws", "10.1.1.14", 44818, "Engineering workstation to PLC main compat listener"),
    ("L2", "engineer-ws", "10.1.2.15", 44818, "Engineering workstation to PLC backup compat listener"),
    ("L2", "hmi", "10.1.1.14", 502, "HMI to PLC main Modbus"),
    ("L2", "hmi", "10.1.2.15", 502, "HMI to PLC backup Modbus"),
]

PLC_CHANNEL_PATHS = [
    ("L1", "plc-main", "10.1.1.10", 1, "PLC main to Channel A"),
    ("L1", "plc-main", "10.1.1.11", 2, "PLC main to Channel B"),
    ("L1", "plc-main", "10.1.1.12", 3, "PLC main to Channel C"),
    ("L1", "plc-backup", "10.1.2.11", 2, "PLC backup to Channel B"),
    ("L1", "plc-backup", "10.1.2.12", 3, "PLC backup to Channel C"),
    ("L1", "plc-backup", "10.1.2.13", 4, "PLC backup to Channel D"),
]

CHANNEL_FIELD_PATHS = [
    ("L0", "channel-a", "10.1.1.9", 1, "Channel A to PT-455"),
    ("L0", "channel-b", "10.1.1.8", 2, "Channel B to PT-456"),
]

POLICY_CHECKS = [
    ("allow", "metasploit", "10.3.50.10", 443, "L4 to historian status"),
    ("allow", "metasploit", "10.3.50.10", 4840, "L4 to historian north-south path"),
    ("allow", "hmi", "10.3.50.10", 443, "L2 HMI to historian status"),
    ("allow", "engineer-ws", "10.3.50.10", 4840, "L2 engineering to historian OPC/status"),
    ("allow", "hmi", "10.1.1.14", 502, "L2 to PLC main Modbus"),
    ("allow", "engineer-ws", "10.1.2.15", 44818, "L2 to PLC backup compat listener"),
    ("allow", "historian", "10.4.50.20", 5432, "historian to postgres"),
    ("blocked", "metasploit", "10.2.50.10", 443, "L4 blocked from HMI"),
    ("blocked", "metasploit", "10.1.1.14", 502, "L4 blocked from PLC main"),
    ("blocked", "hmi", "10.4.50.20", 5432, "L2 blocked from enterprise database"),
    ("blocked", "engineer-ws", "10.4.50.10", 4444, "L2 blocked from metasploit RPC"),
    ("blocked", "hmi", "10.1.1.9", 502, "L2 blocked from direct field PT-455"),
    ("blocked", "historian", "10.1.1.9", 502, "L3 blocked from direct field PT-455"),
]


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


def load_compose(compose_file: Path) -> dict:
    return json.loads(docker_compose(compose_file, ["config", "--format", "json"]))


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
        time.sleep(5)
    raise SystemExit(
        "services did not reach running state: "
        + json.dumps({"last_seen": last_seen}, indent=2)
    )


def docker_exec(container_name: str, argv: list[str]) -> str:
    return run(["docker", "exec", container_name, *argv])


def probe_tcp(container_name: str, host: str, port: int, timeout_sec: float = 3.0) -> bool:
    snippet = r"""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout_sec = float(sys.argv[3])

with socket.create_connection((host, port), timeout=timeout_sec):
    pass
print("ok")
"""
    try:
        docker_exec(
            container_name,
            ["python3", "-c", snippet, host, str(port), str(timeout_sec)],
        )
        return True
    except subprocess.CalledProcessError:
        return False


def read_json_url(container_name: str, url: str) -> dict:
    snippet = (
        "import json, urllib.request; "
        f"print(json.dumps(json.load(urllib.request.urlopen('{url}', timeout=4))))"
    )
    output = docker_exec(container_name, ["python3", "-c", snippet])
    return json.loads(output)


def read_opc(endpoint: str, namespace: str) -> dict[str, int]:
    output = docker_exec(
        "engineer-ws",
        [
            "opc-read",
            endpoint,
            "--namespace",
            namespace,
        ],
    )
    return json.loads(output)


def wait_for_opc_bridge(
    endpoint: str,
    namespace: str,
    timeout_sec: int = 20,
) -> dict[str, int]:
    deadline = time.time() + timeout_sec
    last_values: dict[str, int] = {}
    while time.time() < deadline:
        last_values = read_opc(endpoint, namespace)
        if int(last_values.get("bridge_online", 0)) == 1 and int(last_values.get("health_code", 0)) == 1:
            return last_values
        time.sleep(2)
    raise SystemExit(
        f"OPC bridge did not become healthy for {endpoint}: "
        + json.dumps(last_values, sort_keys=True)
    )


def read_modbus_via_container(
    container_name: str,
    host: str,
    port: int,
    unit_id: int,
    function: int,
    start: int,
    count: int,
) -> list[int]:
    snippet = r"""
import json
import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2])
unit = int(sys.argv[3])
function = int(sys.argv[4])
start = int(sys.argv[5])
count = int(sys.argv[6])

request = struct.pack(">HHHBBHH", 1, 0, 6, unit, function, start, count)
with socket.create_connection((host, port), timeout=3) as sock:
    sock.sendall(request)
    header = sock.recv(7)
    body = sock.recv(struct.unpack(">H", header[4:6])[0] - 1)

if body[0] & 0x80:
    raise SystemExit(f"Modbus exception {body[1]}")

values = [struct.unpack(">H", body[2+i:4+i])[0] for i in range(0, body[1], 2)]
print(json.dumps(values))
"""
    output = docker_exec(
        container_name,
        [
            "python3",
            "-c",
            snippet,
            host,
            str(port),
            str(unit_id),
            str(function),
            str(start),
            str(count),
        ],
    )
    return json.loads(output)


def record(checks: list[tuple[str, str]], condition: bool, label: str, detail: str) -> None:
    if not condition:
        raise SystemExit(f"{label} failed: {detail}")
    checks.append((label, detail))


def exercise_north_south_traffic(
    checks: list[tuple[str, str]],
    iterations: int,
) -> dict[str, int]:
    layer_counts = {"L4": 0, "L3": 0, "L2": 0}
    for iteration in range(iterations):
        for layer, source_container, host, port, label in LAYER_TRAFFIC_PATHS:
            connected = probe_tcp(source_container, host, port)
            record(
                checks,
                connected,
                f"{label} (traffic exercise {iteration + 1}/{iterations})",
                f"{source_container} -> {host}:{port}",
            )
            layer_counts[layer] += 1
    return layer_counts


def exercise_control_and_field_paths(
    checks: list[tuple[str, str]],
    iterations: int,
) -> dict[str, int]:
    layer_counts = {"L1": 0, "L0": 0}
    for iteration in range(iterations):
        for layer, source_container, host, unit_id, label in PLC_CHANNEL_PATHS:
            registers = read_modbus_via_container(source_container, host, 502, unit_id, 4, 0, 2)
            record(
                checks,
                int(registers[1]) == 1,
                f"{label} (traffic exercise {iteration + 1}/{iterations})",
                f"value={registers[0]} status={registers[1]}",
            )
            layer_counts[layer] += 1
        for layer, source_container, host, unit_id, label in CHANNEL_FIELD_PATHS:
            registers = read_modbus_via_container(source_container, host, 502, unit_id, 4, 0, 2)
            record(
                checks,
                int(registers[1]) == 1,
                f"{label} (traffic exercise {iteration + 1}/{iterations})",
                f"value={registers[0]} status={registers[1]}",
            )
            layer_counts[layer] += 1
    return layer_counts


def verify_field_to_plc(checks: list[tuple[str, str]]) -> dict[str, dict[str, int]]:
    opc_results: dict[str, dict[str, int]] = {}
    for profile, (endpoint, namespace) in OPC_TARGETS.items():
        values = wait_for_opc_bridge(endpoint, namespace)
        opc_results[profile] = values
        record(
            checks,
            int(values.get("bridge_online", 0)) == 1,
            f"{profile} OPC bridge online",
            f"bridge_online={values.get('bridge_online')}",
        )

    for profile, paths in FIELD_PATHS.items():
        opc_values = opc_results[profile]
        field_values = []
        for point_name, source_container, host, unit_id in paths:
            registers = read_modbus_via_container(source_container, host, 502, unit_id, 4, 0, 2)
            field_value = int(registers[0])
            field_values.append(field_value)
            record(
                checks,
                int(registers[1]) == 1,
                f"{profile} {point_name} status",
                f"value={field_value} status={registers[1]}",
            )
        average_pressure = int(opc_values.get("average_pressure", -1))
        expected_average = sum(field_values) // len(field_values)
        record(
            checks,
            abs(average_pressure - expected_average) <= POINT_TOLERANCE,
            f"{profile} average pressure summary",
            f"average={average_pressure} expected={expected_average}",
        )

    return opc_results


def verify_hmi_and_historian(checks: list[tuple[str, str]]) -> tuple[dict, dict]:
    hmi_state = read_json_url("hmi", "http://127.0.0.1/api/state")
    for name in ("plc-main", "plc-backup"):
        plc_state = hmi_state["plcs"][name]
        record(
            checks,
            bool(plc_state.get("connected")),
            f"HMI connected to {name}",
            plc_state.get("error", ""),
        )
        values = plc_state.get("values", {})
        point_keys = HMI_POINT_KEYS[name]
        point_values = [int(values.get(key, -1)) for key in point_keys]
        record(
            checks,
            all(value >= 0 for value in point_values),
            f"HMI values present for {name}",
            json.dumps({key: values.get(key) for key in point_keys}, sort_keys=True),
        )
        average_pressure = int(values.get("average_pressure", -1))
        expected_average = sum(point_values) // len(point_values)
        record(
            checks,
            abs(average_pressure - expected_average) <= POINT_TOLERANCE,
            f"HMI average pressure for {name}",
            f"average={average_pressure} expected={expected_average}",
        )

    historian_state = read_json_url("historian", "http://127.0.0.1:443")
    record(
        checks,
        historian_state.get("status") == "ok",
        "historian status",
        historian_state.get("status", "unknown"),
    )
    for profile in ("main", "backup"):
        profile_state = historian_state["profiles"][profile]
        record(
            checks,
            bool(profile_state.get("connected")),
            f"historian connected to {profile} OPC",
            json.dumps(profile_state.get("values", {}), sort_keys=True)[:160],
        )
    return hmi_state, historian_state


def verify_policy(checks: list[tuple[str, str]]) -> None:
    for expected, source_container, host, port, label in POLICY_CHECKS:
        connected = probe_tcp(source_container, host, port)
        if expected == "allow":
            record(checks, connected, label, f"{source_container} -> {host}:{port}")
        else:
            record(checks, not connected, label, f"{source_container} -> {host}:{port}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the hybrid IAEA RCS runtime from field paths up through Layer 4"
    )
    parser.add_argument(
        "--compose-file",
        default=str(DEFAULT_COMPOSE_FILE),
        help=f"Compose file to verify (default: {DEFAULT_COMPOSE_FILE})",
    )
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=900,
        help="How long to wait for services to reach running state",
    )
    parser.add_argument(
        "--traffic-iterations",
        type=int,
        default=2,
        help="How many active traffic passes to drive through each layer before validation",
    )
    args = parser.parse_args()

    compose_file = Path(args.compose_file).resolve()
    checks: list[tuple[str, str]] = []

    wait_for_running_services(compose_file, CORE_REQUIRED_SERVICES, args.timeout_sec)
    checks.append(("services running", f"{len(CORE_REQUIRED_SERVICES)} core services"))

    layer_traffic = {}
    layer_traffic.update(exercise_north_south_traffic(checks, max(1, args.traffic_iterations)))
    layer_traffic.update(exercise_control_and_field_paths(checks, max(1, args.traffic_iterations)))
    opc_results = verify_field_to_plc(checks)
    hmi_state, historian_state = verify_hmi_and_historian(checks)
    verify_policy(checks)

    print("Hybrid runtime verification passed")
    for label, detail in checks:
        print(f"[ok] {label}: {detail}")
    print(
        json.dumps(
            {
                "layer_traffic": layer_traffic,
                "opc": opc_results,
                "hmi": hmi_state,
                "historian": historian_state,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
