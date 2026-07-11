#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mirror all ingress traffic from one host interface to another using tc mirred."
    )
    parser.add_argument(
        "from_iface",
        nargs="?",
        help="source host interface to mirror from (for example docker0 or br_rcs_l2)",
    )
    parser.add_argument("container_id", nargs="?", help="target container ID or name to mirror traffic to")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="list currently configured tc mirroring rules",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="clear mirroring rule for the given from_iface and container_id",
    )
    return parser.parse_args()


def run_command(command: list[str], echo: bool = True) -> subprocess.CompletedProcess[str]:
    if echo:
        print("+", " ".join(shlex.quote(part) for part in command))
    return subprocess.run(command, check=False, text=True, capture_output=True)


def ensure_container_running(container_id: str) -> None:
    result = run_command(["docker", "inspect", "-f", "{{.State.Running}}", container_id])
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise SystemExit(f"failed to inspect container {container_id}: {stderr}")
    if result.stdout.strip().lower() != "true":
        raise SystemExit(f"container is not running: {container_id}")


def get_container_eth0_iflink(container_id: str) -> str:
    result = run_command(["docker", "exec", container_id, "cat", "/sys/class/net/eth0/iflink"])
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise SystemExit(f"failed to read eth0 iflink for {container_id}: {stderr}")

    iflink = result.stdout.strip()
    if not iflink.isdigit():
        raise SystemExit(f"unexpected iflink value for {container_id}: {iflink}")
    return iflink


def resolve_host_veth_for_container(container_id: str) -> str:
    target_ifindex = get_container_eth0_iflink(container_id)
    veth_matches: list[str] = []

    for ifindex_path in sorted(glob.glob("/sys/class/net/veth*/ifindex")):
        try:
            value = Path(ifindex_path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value == target_ifindex:
            veth_matches.append(Path(ifindex_path).parent.name)

    if not veth_matches:
        raise SystemExit(
            f"no host veth found for container {container_id} (target ifindex {target_ifindex})"
        )
    if len(veth_matches) > 1:
        raise SystemExit(
            f"multiple host veth matches for container {container_id}: {', '.join(veth_matches)}"
        )
    return veth_matches[0]


def ensure_interface_exists(iface: str) -> None:
    result = run_command(["ip", "link", "show", "dev", iface])
    if result.returncode != 0:
        raise SystemExit(f"interface not found: {iface}")


def ensure_ingress_qdisc(from_iface: str) -> None:
    show_result = run_command(["tc", "qdisc", "show", "dev", from_iface])
    if show_result.returncode != 0:
        stderr = show_result.stderr.strip()
        raise SystemExit(f"failed to read qdisc state for {from_iface}: {stderr}")

    if "ingress" in show_result.stdout:
        print(f"ingress qdisc already present on {from_iface}")
        return

    add_result = run_command(
        ["tc", "qdisc", "add", "dev", from_iface, "handle", "ffff:", "ingress"],
    )
    if add_result.returncode != 0:
        stderr = add_result.stderr.strip()
        raise SystemExit(f"failed to add ingress qdisc on {from_iface}: {stderr}")


def install_mirror_filter(from_iface: str, to_iface: str) -> None:
    replace_result = run_command(
        [
            "tc",
            "filter",
            "replace",
            "dev",
            from_iface,
            "parent",
            "ffff:",
            "protocol",
            "all",
            "pref",
            "1",
            "u32",
            "match",
            "u32",
            "0",
            "0",
            "action",
            "mirred",
            "egress",
            "mirror",
            "dev",
            to_iface,
        ],
    )
    if replace_result.returncode != 0:
        stderr = replace_result.stderr.strip()
        raise SystemExit(f"failed to install mirror filter from {from_iface} to {to_iface}: {stderr}")


def list_host_interfaces() -> list[str]:
    result = run_command(["ip", "-o", "link", "show"], echo=False)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise SystemExit(f"failed to list host interfaces: {stderr}")

    names: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        iface = parts[1].strip()
        if "@" in iface:
            iface = iface.split("@", 1)[0]
        if iface:
            names.append(iface)
    return names


def collect_mirroring_rules() -> list[tuple[str, str, str]]:
    mirror_entries: list[tuple[str, str, str]] = []
    device_pattern = re.compile(r"to device\s+(\S+)\)")

    for iface in list_host_interfaces():
        result = run_command(["tc", "filter", "show", "dev", iface, "parent", "ffff:"], echo=False)
        if result.returncode != 0:
            continue

        for line in result.stdout.splitlines():
            lowered = line.lower()
            if "mirred" not in lowered or "mirror" not in lowered:
                continue
            match = device_pattern.search(line)
            target_iface = match.group(1) if match else "unknown"
            mirror_entries.append((iface, target_iface, line.strip()))

    return mirror_entries


def get_running_container_ids() -> list[str]:
    result = run_command(["docker", "ps", "-q"], echo=False)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_container_name(container_id: str) -> str | None:
    result = run_command(["docker", "inspect", "-f", "{{.Name}}", container_id], echo=False)
    if result.returncode != 0:
        return None
    name = result.stdout.strip().lstrip("/")
    return name or None


def resolve_host_veth_from_iflink(iflink: str) -> str | None:
    for ifindex_path in sorted(glob.glob("/sys/class/net/veth*/ifindex")):
        try:
            value = Path(ifindex_path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value == iflink:
            return Path(ifindex_path).parent.name
    return None


def build_veth_to_container_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for container_id in get_running_container_ids():
        iflink_result = run_command(
            ["docker", "exec", container_id, "cat", "/sys/class/net/eth0/iflink"],
            echo=False,
        )
        if iflink_result.returncode != 0:
            continue
        iflink = iflink_result.stdout.strip()
        if not iflink.isdigit():
            continue

        veth = resolve_host_veth_from_iflink(iflink)
        if not veth:
            continue

        name = get_container_name(container_id)
        if not name:
            continue
        mapping[veth] = name
    return mapping


def verify_mirroring_rules() -> int:
    mirror_entries = collect_mirroring_rules()
    veth_to_container = build_veth_to_container_map()

    if not mirror_entries:
        print("no tc mirroring rules found")
        return 0

    print("configured tc mirroring rules:")
    for from_iface, to_iface, detail in mirror_entries:
        target_name = veth_to_container.get(to_iface, "unknown-container")
        print(f"- {from_iface} -> {target_name}")
        print(f"  {detail}")

    return 0


def clear_mirroring_rule(from_iface: str, container_id: str) -> int:
    ensure_container_running(container_id)
    to_iface = resolve_host_veth_for_container(container_id)

    mirror_entries = collect_mirroring_rules()
    matches = [entry for entry in mirror_entries if entry[0] == from_iface and entry[1] == to_iface]
    if not matches:
        print(f"no tc mirroring rule found for {from_iface} -> {to_iface}")
        return 0

    result = run_command([
        "tc",
        "filter",
        "del",
        "dev",
        from_iface,
        "parent",
        "ffff:",
        "protocol",
        "all",
        "pref",
        "1",
        "u32",
    ])
    if result.returncode != 0:
        raise SystemExit(f"failed to clear mirroring rule on {from_iface}: {result.stderr.strip()}")

    print(f"resolved host veth for {container_id}: {to_iface}")
    print(f"cleared tc mirroring rule: {from_iface} -> {to_iface}")
    return 0


def main() -> int:
    args = parse_args()

    if args.verify and args.clear:
        raise SystemExit("choose only one of --verify or --clear")

    if args.verify:
        return verify_mirroring_rules()

    if args.clear:
        if not args.from_iface or not args.container_id:
            raise SystemExit("from_iface and container_id are required when using --clear")
        if os.geteuid() != 0:
            raise SystemExit("Please run this script as root.")
        return clear_mirroring_rule(args.from_iface, args.container_id)

    if not args.from_iface or not args.container_id:
        raise SystemExit("from_iface and container_id are required unless using --verify or --clear")

    if os.geteuid() != 0:
        raise SystemExit("Please run this script as root.")

    ensure_container_running(args.container_id)
    to_iface = resolve_host_veth_for_container(args.container_id)

    ensure_interface_exists(args.from_iface)
    ensure_interface_exists(to_iface)

    ensure_ingress_qdisc(args.from_iface)
    install_mirror_filter(args.from_iface, to_iface)

    print(f"resolved host veth for {args.container_id}: {to_iface}")
    print(f"mirroring enabled: {args.from_iface} -> {to_iface}")
    print(f"verify with: tc filter show dev {args.from_iface} parent ffff:")

    return 0


if __name__ == "__main__":
    sys.exit(main())
