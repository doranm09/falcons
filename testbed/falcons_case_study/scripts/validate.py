#!/usr/bin/env python3
"""Validate the FALCONS publication case-study topology and policy."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
POLICY = ROOT / "allowed_communications.json"
MODEL = ROOT / "sim_system.json"

REQUIRED_SERVICES = {
    "enterprise-ws-1",
    "enterprise-ws-2",
    "enterprise-export-receiver",
    "data-diode",
    "historian",
    "historian-exporter",
    "hmi",
    "operator-ws",
    "gateway-0",
    "plc-main",
    "plc-backup",
    "channel-a",
    "channel-b",
    "channel-c",
    "channel-d",
    "pt-455",
    "pt-456",
}

REQUIRED_MODEL_NODES = {
    "enterprise-ws-1",
    "enterprise-ws-2",
    "data-diode",
    "historian",
    "hmi",
    "operator-ws",
    "gateway-0",
    "plc-main",
    "plc-backup",
    "channel-a",
    "channel-b",
    "channel-c",
    "channel-d",
    "pt-455",
    "pt-456",
    "pt-457",
    "pt-458",
    "maintain_pressure",
}

PLANT_NETWORKS = {
    "enterprise_net",
    "operations_net",
    "supervisory_net",
    "control_a",
    "control_b",
}


class ValidationError(RuntimeError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc
    check(isinstance(payload, dict), f"{path.name} must contain a JSON object")
    return payload


def run(command: list[str], *, check_result: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if check_result and completed.returncode != 0:
        raise ValidationError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def compose_json() -> dict[str, Any] | None:
    if shutil.which("docker") is None:
        return None
    completed = run(
        ["docker", "compose", "-f", str(COMPOSE), "config", "--format", "json"],
        check_result=False,
    )
    if completed.returncode != 0:
        # Older Compose releases may not support JSON output. Still require the
        # ordinary schema/config validation to pass.
        run(["docker", "compose", "-f", str(COMPOSE), "config", "--quiet"])
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"docker compose returned invalid JSON: {exc}") from exc
    check(isinstance(payload, dict), "normalized Compose document must be an object")
    return payload


def normalized_networks(service: dict[str, Any]) -> set[str]:
    raw = service.get("networks") or {}
    if isinstance(raw, dict):
        return {str(name) for name in raw}
    if isinstance(raw, list):
        return {str(name) for name in raw}
    return set()


def validate_compose() -> None:
    check(COMPOSE.is_file(), f"missing {COMPOSE}")
    text = COMPOSE.read_text(encoding="utf-8")
    for token in (
        "name: falcons_case_study",
        "data-diode:",
        "gateway-0:",
        "DIODE_PROTOCOL: udp",
        'net.ipv4.ip_forward: "0"',
        "enterprise_net:",
        "operations_net:",
        "supervisory_net:",
        "control_a:",
        "control_b:",
    ):
        check(token in text, f"Compose file is missing required declaration: {token}")

    normalized = compose_json()
    if normalized is None:
        print("compose: textual checks passed (normalized JSON unavailable)")
        return

    services = normalized.get("services") or {}
    check(isinstance(services, dict), "normalized Compose services must be an object")
    missing = sorted(REQUIRED_SERVICES - set(services))
    check(not missing, f"Compose is missing required services: {missing}")

    expected_networks = {
        "enterprise-ws-1": {"enterprise_net", "oob_mgmt"},
        "enterprise-ws-2": {"enterprise_net", "oob_mgmt"},
        "data-diode": {"enterprise_net", "operations_net"},
        "historian": {"operations_net", "supervisory_net", "oob_mgmt"},
        "hmi": {"supervisory_net", "oob_mgmt"},
        "operator-ws": {"supervisory_net", "oob_mgmt"},
        "gateway-0": {"supervisory_net", "control_a", "control_b"},
        "plc-main": {"control_a", "control_b", "oob_mgmt"},
        "plc-backup": {"control_a", "control_b", "oob_mgmt"},
        "channel-a": {"control_a", "control_b", "oob_mgmt"},
        "channel-b": {"control_a", "control_b", "oob_mgmt"},
        "channel-c": {"control_a", "control_b", "oob_mgmt"},
        "channel-d": {"control_a", "control_b", "oob_mgmt"},
        "pt-455": {"control_a", "control_b", "oob_mgmt"},
        "pt-456": {"control_a", "control_b", "oob_mgmt"},
    }
    for service_name, expected in expected_networks.items():
        actual = normalized_networks(services[service_name])
        check(actual == expected, f"{service_name} networks {sorted(actual)} != {sorted(expected)}")

    for service_name, service in services.items():
        networks = normalized_networks(service)
        crosses_supervisory_control = "supervisory_net" in networks and bool(
            networks & {"control_a", "control_b"}
        )
        if crosses_supervisory_control:
            check(service_name == "gateway-0", f"{service_name} creates an unauthorized Supervisory-Control route")

        crosses_enterprise_operations = "enterprise_net" in networks and "operations_net" in networks
        if crosses_enterprise_operations:
            check(service_name == "data-diode", f"{service_name} bypasses the data diode")

    networks = normalized.get("networks") or {}
    for network_name in PLANT_NETWORKS:
        record = networks.get(network_name) or {}
        check(bool(record.get("internal")), f"plant network {network_name} must be internal")

    print("compose: normalized topology checks passed")


def iter_policy_destinations(record: dict[str, Any]) -> list[str]:
    value = record.get("destination")
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)] if value else []


def validate_policy() -> None:
    policy = load_json(POLICY)
    check(policy.get("default_action") == "deny", "policy default_action must be deny")
    boundaries = policy.get("boundaries") or {}
    diode = boundaries.get("data-diode") or {}
    check(diode.get("reverse_allowed") is False, "data-diode must explicitly deny reverse transfer")
    gateway = boundaries.get("gateway-0") or {}
    check(gateway.get("default_action") == "deny", "Gateway-0 must use default deny")

    communications = policy.get("communications") or []
    check(isinstance(communications, list), "policy communications must be a list")
    exports = [row for row in communications if isinstance(row, dict) and row.get("boundary") == "data-diode"]
    check(len(exports) == 1, "policy must contain exactly one data-diode communication")
    export = exports[0]
    check(export.get("source") == "historian", "data-diode source must be historian")
    check(iter_policy_destinations(export) == ["enterprise-ws-1"], "data-diode destination must be enterprise-ws-1")
    check(str(export.get("protocol")).lower() == "udp", "data-diode transport must be UDP")
    check(export.get("destination_ports") == [5514], "data-diode destination port must be 5514")

    reverse = [
        row
        for row in communications
        if isinstance(row, dict)
        and row.get("source") in {"enterprise-ws-1", "enterprise-ws-2"}
        and "historian" in iter_policy_destinations(row)
    ]
    check(not reverse, "policy contains an Enterprise-to-Historian reverse path")
    print("policy: one-way and service-aware checks passed")


def validate_model() -> None:
    model = load_json(MODEL)
    sections = {name: model.get(name) or {} for name in ("digital", "physical", "flow", "function")}
    for name, section in sections.items():
        check(isinstance(section, dict), f"model section {name} must be an object")
    node_ids = set().union(*(set(section) for section in sections.values()))
    missing = sorted(REQUIRED_MODEL_NODES - node_ids)
    check(not missing, f"sim_system is missing required nodes: {missing}")

    metadata = model.get("metadata") or {}
    process_source = metadata.get("process_source") or {}
    check(
        process_source.get("publication_approved") is False,
        "initial integration model must not accidentally claim publication-approved GPWR provenance",
    )

    digital = sections["digital"]
    check((digital.get("data-diode") or {}).get("boundary_policy", {}).get("reverse_allowed") is False,
          "model data-diode must deny reverse transfer")
    gateway_targets = set((digital.get("gateway-0") or {}).get("target") or {})
    check(gateway_targets == {"plc-main", "plc-backup"}, "Gateway-0 must target only the two PLCs")
    print("model: required cyber-physical nodes and boundaries passed")


def validate_runtime() -> None:
    check(shutil.which("docker") is not None, "Docker is required for --runtime")
    running = run(
        ["docker", "compose", "-f", str(COMPOSE), "ps", "--services", "--status", "running"]
    ).stdout.splitlines()
    missing = sorted(REQUIRED_SERVICES - set(running))
    check(not missing, f"runtime services are not running: {missing}")

    diode_rules = run(
        ["docker", "compose", "-f", str(COMPOSE), "exec", "-T", "data-diode", "iptables", "-S", "FORWARD"]
    ).stdout
    check("-P FORWARD DROP" in diode_rules, "data-diode FORWARD policy is not DROP")
    check("10.3.50.10/32" in diode_rules and "10.4.50.10/32" in diode_rules and "--dport 5514" in diode_rules,
          "data-diode exact historian export rule is missing")
    check("ESTABLISHED,RELATED" not in diode_rules, "data-diode contains a reverse-capable stateful forwarding rule")

    gateway_rules = run(
        ["docker", "compose", "-f", str(COMPOSE), "exec", "-T", "gateway-0", "iptables", "-S", "FORWARD"]
    ).stdout
    check("-P FORWARD DROP" in gateway_rules, "Gateway-0 FORWARD policy is not DROP")
    check("10.2.50.10/32" in gateway_rules, "Gateway-0 HMI allow rules are missing")
    check("10.2.50.20/32" in gateway_rules, "Gateway-0 workstation allow rules are missing")
    check("10.2.50.30/32" in gateway_rules, "Gateway-0 historian allow rules are missing")

    export_log = run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "exec",
            "-T",
            "enterprise-export-receiver",
            "sh",
            "-c",
            "test -s /data/historian-export.jsonl && tail -n 1 /data/historian-export.jsonl",
        ]
    ).stdout.strip()
    check(bool(export_log), "no historian export has crossed the data diode")
    print("runtime: boundary rules and one-way export evidence passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", action="store_true", help="also inspect running containers and boundary rules")
    args = parser.parse_args()

    try:
        validate_compose()
        validate_policy()
        validate_model()
        if args.runtime:
            validate_runtime()
    except ValidationError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print("FALCONS case-study validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
