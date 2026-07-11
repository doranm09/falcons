#!/usr/bin/env python3
from __future__ import annotations

"""Legacy pre-hybrid topology verifier retained for reference.

For the current validated demo path, use `verify_hybrid_runtime.py` instead.
"""

import ipaddress
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "docker-compose.yml"
PROJECT_NAME = ROOT.name

MAIN_OPC = ("opc.tcp://10.1.13.10:4840/main", "urn:iaea-rcs-demo:main")
BACKUP_OPC = ("opc.tcp://10.2.23.10:4840/backup", "urn:iaea-rcs-demo:backup")

MAIN_PT_TARGETS = [
    ("pt455", "10.3.13.11", 1),
    ("pt456", "10.3.13.12", 2),
    ("pt457", "10.3.13.13", 3),
]
BACKUP_PT_TARGETS = [
    ("pt456", "10.4.23.12", 2),
    ("pt457", "10.4.23.13", 3),
    ("pt458", "10.4.23.14", 4),
]

SUMMARY_KEYS = {
    "main": ["exported_pt455", "exported_pt456", "exported_pt457"],
    "backup": ["exported_pt456", "exported_pt457", "exported_pt458"],
}

AVERAGE_TOLERANCE = 8
POINT_TOLERANCE = 8


def run(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=str(cwd or ROOT),
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def docker_compose(args: list[str]) -> str:
    return run(["docker", "compose", "-f", COMPOSE_FILE.name, *args], cwd=ROOT)


def load_compose() -> dict:
    return json.loads(docker_compose(["config", "--format", "json"]))


def load_compose_ps() -> list[dict]:
    output = docker_compose(["ps", "--format", "json"]).strip()
    if not output:
        return []
    try:
        rows = json.loads(output)
        if isinstance(rows, list):
            return rows
    except json.JSONDecodeError:
        pass
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def normalize_environment(raw_environment: object) -> dict[str, str]:
    if isinstance(raw_environment, dict):
        return {str(key): str(value) for key, value in raw_environment.items()}

    environment: dict[str, str] = {}
    for item in raw_environment or []:
        key, _, value = str(item).partition("=")
        environment[key] = value
    return environment


def inspect_container(container_name: str) -> dict:
    return json.loads(run(["docker", "inspect", container_name]))[0]


def inspect_network(network_name: str) -> dict:
    return json.loads(run(["docker", "network", "inspect", network_name]))[0]


def find_network_attachment(expected_name: str, networks: dict[str, dict]) -> tuple[str, dict]:
    for actual_name, details in networks.items():
        if actual_name == expected_name or actual_name.endswith(f"_{expected_name}"):
            return actual_name, details
    raise RuntimeError(f"missing expected network attachment {expected_name}")


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
print(values)
"""
    output = run(
        [
            "docker",
            "exec",
            container_name,
            "python3",
            "-c",
            snippet,
            host,
            str(port),
            str(unit_id),
            str(function),
            str(start),
            str(count),
        ]
    ).strip()
    return json.loads(output.replace("'", '"'))


def read_opc(endpoint: str, namespace: str) -> dict[str, int]:
    output = run(
        [
            "docker",
            "exec",
            "engineer-ws",
            "opc-read",
            endpoint,
            "--namespace",
            namespace,
        ]
    )
    return json.loads(output)


def wait_for_running_services(expected_services: set[str], timeout_sec: int = 900) -> list[dict]:
    deadline = time.time() + timeout_sec
    last_seen = []
    while time.time() < deadline:
        rows = load_compose_ps()
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
            return rows
        time.sleep(5)
    raise SystemExit(
        "services did not reach running state: "
        + json.dumps({"last_seen": last_seen}, indent=2)
    )


def verify_network_inventory(compose: dict) -> list[dict[str, object]]:
    expected_networks = compose["networks"]
    service_configs = compose["services"]
    findings: list[dict[str, object]] = []
    actual_network_names: set[str] = set()

    for service_name, config in service_configs.items():
        container_name = config.get("container_name", service_name)
        inspect_data = inspect_container(container_name)
        actual_networks = inspect_data["NetworkSettings"]["Networks"]
        declared_networks = config.get("networks", {})
        if not declared_networks:
            continue
        for network_name, network_config in declared_networks.items():
            actual_name, actual_details = find_network_attachment(network_name, actual_networks)
            actual_network_names.add(actual_name)
            expected_ip = None
            if isinstance(network_config, dict):
                expected_ip = network_config.get("ipv4_address")
            actual_ip = str(actual_details.get("IPAddress", "")).split("/")[0]
            if expected_ip and actual_ip != expected_ip:
                raise SystemExit(
                    f"{service_name} has {actual_ip} on {network_name}, expected {expected_ip}"
                )
            findings.append(
                {
                    "service": service_name,
                    "container": container_name,
                    "network": network_name,
                    "actual_network": actual_name,
                    "ip": actual_ip,
                }
            )

    for network_name in expected_networks:
        actual_name = f"{PROJECT_NAME}_{network_name}"
        inspect_network(actual_name)
        actual_network_names.add(actual_name)

    return findings


def verify_digital_field_devices(compose: dict) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    network_cidrs = {
        name: ipaddress.ip_network(config["ipam"]["config"][0]["subnet"])
        for name, config in compose["networks"].items()
    }

    for service_name, config in compose["services"].items():
        environment = normalize_environment(config.get("environment", {}))
        profile = environment.get("MODBUS_PROFILE", "").strip().lower()
        if profile not in {"pressure_transmitter", "actuator"}:
            continue

        networks = config.get("networks", {})
        if not networks:
            raise SystemExit(f"{service_name} has MODBUS_PROFILE={profile} but no networks")

        addresses = []
        for network_name, network_config in networks.items():
            expected_ip = network_config.get("ipv4_address") if isinstance(network_config, dict) else None
            if not expected_ip:
                continue
            ip_obj = ipaddress.ip_address(expected_ip)
            if ip_obj not in network_cidrs[network_name]:
                raise SystemExit(
                    f"{service_name} IP {expected_ip} is outside declared subnet {network_cidrs[network_name]}"
                )
            addresses.append(f"{network_name}:{expected_ip}")

        findings.append(
            {
                "service": service_name,
                "profile": profile,
                "addresses": addresses,
            }
        )

    return sorted(findings, key=lambda item: item["service"])


def within_envelope(candidate: int, before: int, after: int, tolerance: int) -> bool:
    low = min(before, after) - tolerance
    high = max(before, after) + tolerance
    return low <= candidate <= high


def average(values: list[int]) -> int:
    return round(sum(values) / len(values))


def verify_plc_path(
    plc_container: str,
    pt_targets: list[tuple[str, str, int]],
    opc_endpoint: str,
    opc_namespace: str,
    profile: str,
) -> dict[str, object]:
    pt_before = {
        key: read_modbus_via_container(plc_container, host, 502, unit_id, 4, 0, 2)[0]
        for key, host, unit_id in pt_targets
    }
    summary = read_modbus_via_container(plc_container, "127.0.0.1", 502, 1, 3, 10, 13)
    opc_values = read_opc(opc_endpoint, opc_namespace)
    pt_after = {
        key: read_modbus_via_container(plc_container, host, 502, unit_id, 4, 0, 2)[0]
        for key, host, unit_id in pt_targets
    }

    summary_points = summary[:3]
    for index, key in enumerate(SUMMARY_KEYS[profile]):
        short_key = key.replace("exported_", "")
        if not within_envelope(summary_points[index], pt_before[short_key], pt_after[short_key], POINT_TOLERANCE):
            raise SystemExit(
                f"{plc_container} summary {key}={summary_points[index]} is outside PT envelope "
                f"{pt_before[short_key]}..{pt_after[short_key]}"
            )
        opc_value = int(opc_values[key])
        if not within_envelope(opc_value, pt_before[short_key], pt_after[short_key], POINT_TOLERANCE):
            raise SystemExit(
                f"{plc_container} OPC {key}={opc_value} is outside PT envelope "
                f"{pt_before[short_key]}..{pt_after[short_key]}"
            )

    avg_before = average(list(pt_before.values()))
    avg_after = average(list(pt_after.values()))
    summary_average = int(summary[3])
    opc_average = int(opc_values["average_pressure"])
    if not within_envelope(summary_average, avg_before, avg_after, AVERAGE_TOLERANCE):
        raise SystemExit(
            f"{plc_container} summary average {summary_average} is outside envelope {avg_before}..{avg_after}"
        )
    if not within_envelope(opc_average, avg_before, avg_after, AVERAGE_TOLERANCE):
        raise SystemExit(
            f"{plc_container} OPC average {opc_average} is outside envelope {avg_before}..{avg_after}"
        )

    if int(summary[4]) != 1 or int(opc_values["health_code"]) != 1:
        raise SystemExit(f"{plc_container} health path is not healthy")

    return {
        "plc": plc_container,
        "pt_before": pt_before,
        "pt_after": pt_after,
        "summary_average": summary_average,
        "opc_average": opc_average,
    }


def wait_for_propagation(timeout_sec: int = 180) -> list[dict[str, object]]:
    deadline = time.time() + timeout_sec
    last_error = "not started"
    while time.time() < deadline:
        try:
            return [
                verify_plc_path("plc-main", MAIN_PT_TARGETS, MAIN_OPC[0], MAIN_OPC[1], "main"),
                verify_plc_path("plc-backup", BACKUP_PT_TARGETS, BACKUP_OPC[0], BACKUP_OPC[1], "backup"),
            ]
        except Exception as exc:
            last_error = str(exc)
            time.sleep(3)
    raise SystemExit(f"process-data propagation check timed out: {last_error}")


def main() -> int:
    compose = load_compose()
    expected_services = set(compose["services"])
    ps_rows = wait_for_running_services(expected_services)
    network_findings = verify_network_inventory(compose)
    digital_findings = verify_digital_field_devices(compose)
    propagation_findings = wait_for_propagation()

    print("runtime topology verification passed")
    print(
        json.dumps(
            {
                "services_running": len(ps_rows),
                "expected_services": len(expected_services),
                "network_attachments_verified": len(network_findings),
                "digital_field_devices_verified": digital_findings,
                "process_data_paths": propagation_findings,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
