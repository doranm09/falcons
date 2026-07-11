#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from shlex import quote


@dataclass(frozen=True)
class NetworkInfo:
    docker_name: str
    bridge_name: str
    code: str
    subnet: ipaddress.IPv4Network


NETWORKS = (
    NetworkInfo("iaea_rcs_demo_l4_net", "br_rcs_l4", "l4", ipaddress.ip_network("10.4.50.0/24")),
    NetworkInfo("iaea_rcs_demo_l3_net", "br_rcs_l3", "l3", ipaddress.ip_network("10.3.50.0/24")),
    NetworkInfo("iaea_rcs_demo_l2_net", "br_rcs_l2", "l2", ipaddress.ip_network("10.2.50.0/24")),
    NetworkInfo("iaea_rcs_demo_l1_main", "br_rcs_l1m", "l1m", ipaddress.ip_network("10.1.13.0/24")),
    NetworkInfo("iaea_rcs_demo_l1_backup", "br_rcs_l1b", "l1b", ipaddress.ip_network("10.2.23.0/24")),
    NetworkInfo("iaea_rcs_demo_p13_net", "br_rcs_p13", "p13", ipaddress.ip_network("10.3.13.0/24")),
    NetworkInfo("iaea_rcs_demo_p23_net", "br_rcs_p23", "p23", ipaddress.ip_network("10.4.23.0/24")),
    NetworkInfo("iaea_rcs_demo_mgmt13_net", "br_rcs_m13", "m13", ipaddress.ip_network("10.0.13.0/24")),
    NetworkInfo("iaea_rcs_demo_mgmt23_net", "br_rcs_m23", "m23", ipaddress.ip_network("10.0.23.0/24")),
)

NETWORK_BY_CODE = {network.code: network for network in NETWORKS}
NETWORK_BY_SUBNET = {network.subnet: network for network in NETWORKS}

SERVICE_CODES = {
    "database": "db",
    "metasploit": "msf",
    "historian": "hist",
    "firewall-2": "fw2",
    "firewall-1": "fw1",
    "firewall-0": "fw0",
    "firewall-main-cell": "fwmc",
    "firewall-backup-cell": "fwbc",
    "hmi": "hmi",
    "engineer-ws": "eng",
    "l2-jump": "jump",
    "plc-main": "plcm",
    "plc-backup": "plcb",
    "pt-455": "pt455",
    "pt-456": "pt456",
    "pt-457": "pt457",
    "pt-458": "pt458",
    "vc-hv455a": "hv455a",
    "vc-pv455b": "pv455b",
    "vc-pv455c": "pv455c",
    "heat-ctrl": "heat",
}

LINK_RE = re.compile(r"^(?P<index>\d+): (?P<name>[^:@]+)(?:@[^:]+)?:")
PEER_RE = re.compile(r"@if(?P<peer>\d+):")
ADDR_RE = re.compile(r"^\d+: (?P<ifname>\S+)\s+inet (?P<addr>\d+\.\d+\.\d+\.\d+)/\d+")


def run(*args: str) -> str:
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise SystemExit(f"command failed: {' '.join(args)}: {detail}") from exc
    return result.stdout


def host_links() -> dict[int, str]:
    links: dict[int, str] = {}
    for line in run("ip", "-o", "link", "show").splitlines():
        match = LINK_RE.match(line)
        if match is None:
            continue
        links[int(match.group("index"))] = match.group("name")
    return links


def container_links(container: str) -> dict[str, int]:
    links: dict[str, int] = {}
    output = run("docker", "exec", container, "ip", "-o", "link", "show")
    for line in output.splitlines():
        match = LINK_RE.match(line)
        if match is None:
            continue
        peer_match = PEER_RE.search(line)
        if peer_match is None:
            continue
        links[match.group("name")] = int(peer_match.group("peer"))
    return links


def container_ipv4(container: str) -> dict[str, ipaddress.IPv4Address]:
    addrs: dict[str, ipaddress.IPv4Address] = {}
    output = run("docker", "exec", container, "ip", "-o", "-4", "addr", "show")
    for line in output.splitlines():
        match = ADDR_RE.match(line)
        if match is None:
            continue
        addrs[match.group("ifname")] = ipaddress.ip_address(match.group("addr"))
    return addrs


def running_demo_containers() -> list[str]:
    output = run("docker", "ps", "--format", "{{.Names}}")
    return [name for name in output.splitlines() if name in SERVICE_CODES]


def network_for_ip(address: ipaddress.IPv4Address) -> NetworkInfo | None:
    for subnet, network in NETWORK_BY_SUBNET.items():
        if address in subnet:
            return network
    return None


def desired_veth_name(container: str, network_code: str) -> str:
    service_code = SERVICE_CODES[container]
    name = f"v_{service_code}_{network_code}"
    if len(name) > 15:
        raise ValueError(f"target interface name exceeds 15 chars: {name}")
    return name


def collect_rows() -> list[dict[str, str]]:
    links_by_index = host_links()
    rows: list[dict[str, str]] = []
    for container in sorted(running_demo_containers()):
        peer_by_ifname = container_links(container)
        ipv4_by_ifname = container_ipv4(container)
        for ifname, address in sorted(ipv4_by_ifname.items()):
            if ifname == "lo":
                continue
            network = network_for_ip(address)
            if network is None:
                continue
            peer_index = peer_by_ifname.get(ifname)
            if peer_index is None:
                continue
            host_name = links_by_index.get(peer_index)
            if host_name is None:
                continue
            rows.append(
                {
                    "container": container,
                    "net": network.code,
                    "bridge": network.bridge_name,
                    "ip": str(address),
                    "ctr_if": ifname,
                    "peer_index": str(peer_index),
                    "host_if": host_name,
                    "target_if": desired_veth_name(container, network.code),
                }
            )
    return rows


def apply(rows: list[dict[str, str]]) -> None:
    if os.geteuid() != 0:
        raise SystemExit("re-run with sudo or as root to rename host interfaces")
    claimed_targets: dict[str, str] = {}
    for row in rows:
        current = row["host_if"]
        target = row["target_if"]
        if current == target:
            continue
        if target in claimed_targets and claimed_targets[target] != current:
            raise SystemExit(f"duplicate target interface name requested: {target}")
        claimed_targets[target] = current
        subprocess.run(("ip", "link", "set", "dev", current, "name", target), check=True)


def apply_via_docker(rows: list[dict[str, str]], image: str) -> None:
    commands = []
    claimed_targets: dict[str, str] = {}
    for row in rows:
        current = row["host_if"]
        target = row["target_if"]
        if current == target:
            continue
        if target in claimed_targets and claimed_targets[target] != current:
            raise SystemExit(f"duplicate target interface name requested: {target}")
        claimed_targets[target] = current
        commands.append(f"ip link set dev {quote(current)} name {quote(target)}")

    if not commands:
        return

    script = "set -euo pipefail\n" + "\n".join(commands)
    subprocess.run(
        (
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--network",
            "host",
            "--entrypoint",
            "/bin/bash",
            image,
            "-lc",
            script,
        ),
        check=True,
    )


def print_rows(rows: list[dict[str, str]]) -> None:
    print("Bridges:")
    for network in NETWORKS:
        print(f"  {network.code:<4} {network.bridge_name:<11} {network.docker_name:<24} {network.subnet}")
    print()
    print("Host veth mapping:")
    print("  CONTAINER            NET  CTR_IF  IP             PEER  HOST_IF        TARGET_IF")
    for row in rows:
        print(
            "  "
            f"{row['container']:<20} "
            f"{row['net']:<4} "
            f"{row['ctr_if']:<6} "
            f"{row['ip']:<14} "
            f"{row['peer_index']:<5} "
            f"{row['host_if']:<14} "
            f"{row['target_if']}"
        )


def print_shell(rows: list[dict[str, str]]) -> None:
    for row in rows:
        current = row["host_if"]
        target = row["target_if"]
        if current == target:
            continue
        print(f"ip link set dev {current} name {target}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Show or apply stable host-side bridge and veth names for the IAEA RCS demo."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="rename host-side demo veth interfaces to the TARGET_IF names shown in the table",
    )
    parser.add_argument(
        "--emit-shell",
        action="store_true",
        help="print the ip link rename commands needed to reach the TARGET_IF names",
    )
    parser.add_argument(
        "--apply-via-docker",
        action="store_true",
        help="rename host-side demo veth interfaces through a temporary privileged Docker helper",
    )
    parser.add_argument(
        "--docker-image",
        default="iaea_rcs_demo-engineer-ws",
        help="image to use with --apply-via-docker (default: iaea_rcs_demo-engineer-ws)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = collect_rows()
    if args.emit_shell:
        print_shell(rows)
        return 0
    if args.apply_via_docker:
        apply_via_docker(rows, args.docker_image)
        rows = collect_rows()
        print_rows(rows)
        return 0
    if args.apply:
        apply(rows)
        rows = collect_rows()
    print_rows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
