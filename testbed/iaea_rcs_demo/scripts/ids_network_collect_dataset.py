#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

# Add the ids-network service module to the path
# When running from ids-collector container (host mode), module is in /app
# When running from host, use relative path
if Path("/app/ids_network_common.py").exists():
    sys.path.insert(0, "/app")
else:
    IDS_NETWORK_SERVICE_PATH = Path(__file__).resolve().parent.parent / "services" / "ids-network"
    sys.path.insert(0, str(IDS_NETWORK_SERVICE_PATH))

from ids_network_common import extract_numeric_keys, flow_to_dict, _get_flows_from_argus

# Defaults
DEFAULTS = {
    "interface": "net_10_1_1",
    "kali_container": "kali-attacker",
    "normal_duration": 300,
    "initial_cooldown": 5,
    "scan_rounds": 3,
    "scan_cooldown": 5,
    "attack_label": "attack",
    "normal_label": "normal",
    "label_column": "label",
    "docker_bin": "docker",
}


class PhaseTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phase = "normal"

    def get(self) -> str:
        with self._lock:
            return self._phase

    def set(self, value: str) -> None:
        with self._lock:
            self._phase = value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automate IDS dataset collection on net_10_1_1 using Kali attacker scans."
    )
    parser.add_argument(
        "--interface",
        default=os.environ.get("IDS_NETWORK_IFACE", os.environ.get("IDS_IFACE", DEFAULTS["interface"])),
        help=f"interface to capture from (default: {DEFAULTS['interface']})",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="output path for labeled JSONL dataset",
    )
    parser.add_argument(
        "--normal-duration",
        type=int,
        default=DEFAULTS["normal_duration"],
        help=f"normal traffic capture duration in seconds (default: {DEFAULTS['normal_duration']})",
    )
    parser.add_argument(
        "--initial-cooldown",
        type=int,
        default=DEFAULTS["initial_cooldown"],
        help=f"cool-down seconds after normal capture before attack scans start (default: {DEFAULTS['initial_cooldown']})",
    )
    parser.add_argument(
        "--scan-rounds",
        type=int,
        default=DEFAULTS["scan_rounds"],
        help=f"number of nmap scan rounds to run from Kali (default: {DEFAULTS['scan_rounds']})",
    )
    parser.add_argument(
        "--scan-cooldown",
        type=int,
        default=DEFAULTS["scan_cooldown"],
        help=f"cool-down seconds between attack rounds (default: {DEFAULTS['scan_cooldown']})",
    )
    parser.add_argument(
        "--scan-cidr",
        default=None,
        help="IP range to scan from Kali (auto-detected from target network if omitted, defaults to L1 main: 10.1.1.0/24)",
    )
    parser.add_argument(
        "--attack-ip",
        default=None,
        help="attacker IP address to label as attack traffic (auto-detected from attacker container if omitted)",
    )
    parser.add_argument(
        "--attack-cidr",
        action="append",
        default=[],
        help="additional CIDR network(s) to treat as attack traffic",
    )
    parser.add_argument(
        "--attack-mac",
        action="append",
        default=[],
        help="MAC address to label as attack traffic (source or destination MAC; auto-detected if omitted)",
    )
    parser.add_argument(
        "--attack-label",
        default=DEFAULTS["attack_label"],
        help=f"label value for attack flows (default: {DEFAULTS['attack_label']})",
    )
    parser.add_argument(
        "--normal-label",
        default=DEFAULTS["normal_label"],
        help=f"label value for normal flows (default: {DEFAULTS['normal_label']})",
    )
    parser.add_argument(
        "--label-column",
        default=DEFAULTS["label_column"],
        help=f"output label field name (default: {DEFAULTS['label_column']})",
    )
    parser.add_argument(
        "--kali-container",
        default=os.environ.get("KALI_CONTAINER", DEFAULTS["kali_container"]),
        help=f"Docker Compose service name for the Kali attacker (default: {DEFAULTS['kali_container']})",
    )
    parser.add_argument(
        "--docker-bin",
        default=os.environ.get("DOCKER_BIN", DEFAULTS["docker_bin"]),
        help=f"docker executable path (default: {DEFAULTS['docker_bin']})",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print progress messages during capture",
    )
    return parser.parse_args()


def parse_attack_targets(ip_targets: list[str], cidr_targets: list[str]) -> list[ipaddress._BaseNetwork]:
    """Parse IP addresses and CIDR networks into a list of networks."""
    networks: list[ipaddress._BaseNetwork] = []
    
    for ip_target in ip_targets:
        if not ip_target:
            continue
        try:
            networks.append(ipaddress.ip_network(ip_target, strict=False))
        except ValueError as exc:
            raise SystemExit(f"invalid attack IP target: {ip_target}: {exc}")
    
    for target in cidr_targets:
        try:
            networks.append(ipaddress.ip_network(target, strict=False))
        except ValueError as exc:
            raise SystemExit(f"invalid attack CIDR target: {target}: {exc}")
    
    return networks


def normalize_mac(mac: str) -> str:
    return mac.strip().lower()


def parse_attack_macs(mac_targets: list[str]) -> set[str]:
    """Parse and normalize MAC addresses into a set."""
    return {normalize_mac(target) for target in mac_targets if target}


def discover_attacker_endpoints(
    docker_bin: str,
    container_name: str,
    verbose: bool = False,
) -> tuple[list[str], set[str], str]:
    ips: list[str] = []
    macs: set[str] = set()
    subnet: str = ""

    inspect_cmd = [
        docker_bin,
        "inspect",
        "--format",
        "{{json .NetworkSettings.Networks}}",
        container_name,
    ]
    result = subprocess.run(inspect_cmd, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        try:
            networks = json.loads(result.stdout)
        except json.JSONDecodeError:
            networks = {}
        for net_name, cfg in networks.items():
            ip_addr = (cfg or {}).get("IPAddress", "")
            mac_addr = (cfg or {}).get("MacAddress", "")
            prefix_len = (cfg or {}).get("IPPrefixLen", "")
            if not ip_addr or not prefix_len:
                continue
            if mac_addr:
                macs.add(normalize_mac(mac_addr))
            ips.append(ip_addr)
        # Prefer the first industrial/control network (10.1.x / 10.2.x) as
        # the scan CIDR when the attacker is multi-homed, e.g. on both
        # an API network and the L1 testbed network.
        if not subnet:
            for ip in ips:
                if ip.startswith("10.1.") or ip.startswith("10.2."):
                    for cfg in networks.values():
                        if cfg and cfg.get("IPAddress") == ip:
                            prefix = str(cfg.get("IPPrefixLen", ""))
                            if prefix:
                                subnet = f"{ip}/{prefix}"
                                break
                    if subnet:
                        break
            if not subnet:
                subnet = next(iter(ips), "") + "/0"

        if not ips or not macs:
            if verbose:
                print("inspect failed to return full network details, querying inside container for IP/MAC")

            addr_cmd = [docker_bin, "exec", container_name, "ip", "-4", "-o", "addr", "show", "scope", "global"]
            result = subprocess.run(addr_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    tokens = line.split()
                    for idx, token in enumerate(tokens):
                        if token == "inet" and idx + 1 < len(tokens):
                            ip_with_netmask = tokens[idx + 1]
                            ip = ip_with_netmask.split("/")[0]
                            netmask = ip_with_netmask.split("/")[1] if "/" in ip_with_netmask else ""
                            if ip not in ips:
                                ips.append(ip)
                            if netmask and not subnet:
                                subnet = f"{ip}/{netmask}"

            link_cmd = [docker_bin, "exec", container_name, "ip", "-o", "link", "show"]
            result = subprocess.run(link_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    tokens = line.split()
                    for idx, token in enumerate(tokens):
                        if token == "link/ether" and idx + 1 < len(tokens):
                            macs.add(normalize_mac(tokens[idx + 1]))

    if verbose:
        print(f"discovered attacker IPs: {ips}")
        print(f"discovered attacker MACs: {sorted(macs)}")
        if subnet:
            print(f"discovered attacker subnet: {subnet}")

    return ips, macs, subnet


def is_attack_flow(
    flow: dict,
    attack_networks: list[ipaddress._BaseNetwork],
    attack_macs: set[str],
) -> bool:
    """Check if a flow matches attack criteria by IP or MAC."""
    # Check source/destination IP addresses
    for field in ("saddr", "daddr"):
        value = flow.get(field)
        if not value:
            continue
        try:
            addr = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if any(addr in network for network in attack_networks):
            return True

    # Check source/destination MAC addresses
    for field in ("smac", "dmac"):
        value = flow.get(field)
        if value and str(value).strip().lower() in attack_macs:
            return True

    return False


def write_record_jsonl(output_file: Any, record: dict) -> None:
    output_file.write(json.dumps(record, default=str))
    output_file.write("\n")
    output_file.flush()


def iter_flows_from_interface_subprocess(interface: str, stop_event: threading.Event):
    """Capture flows from a live interface using Argus and stop when requested."""
    argus_file = tempfile.mktemp(prefix="argus_live_", suffix=".argus")
    # -S 1: Flush flows every 1 second to make them available immediately
    cmd = ["argus", "-F", "/dev/null", "-i", interface, "-w", argus_file, "-S", "1"]
    argus_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        last_flow_count = 0
        while not stop_event.is_set():
            try:
                flows = _get_flows_from_argus(argus_file)
                for flow in flows[last_flow_count:]:
                    yield flow_to_dict(flow)
                last_flow_count = len(flows)
            except Exception:
                pass
            time.sleep(0.5)

        # Drain any remaining flows
        try:
            flows = _get_flows_from_argus(argus_file)
            for flow in flows[last_flow_count:]:
                yield flow_to_dict(flow)
        except Exception:
            pass
    finally:
        # Terminate argus process if still running (kill immediately since argus ignores SIGTERM)
        if argus_proc.poll() is None:
            argus_proc.kill()
            try:
                argus_proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        
        # Clean up temp file
        Path(argus_file).unlink(missing_ok=True)


def normalize_flow_record(flow: dict, numeric_keys: list[str]) -> dict:
    row = {key: flow.get(key, 0.0) for key in numeric_keys}
    row.update(
        {
            "saddr": flow.get("saddr", ""),
            "daddr": flow.get("daddr", ""),
            "smac": flow.get("smac", ""),
            "dmac": flow.get("dmac", ""),
            "sport": flow.get("sport", ""),
            "dport": flow.get("dport", ""),
            "proto": flow.get("proto", ""),
        }
    )
    return row


def fatal_error(message: str) -> None:
    print(message, file=sys.stderr)
    os._exit(1)


def resolve_running_container(
    docker_bin: str,
    service_name: str,
    verbose: bool = False,
) -> str:
    """Find the running Kali attacker container by name pattern."""
    cmd = [docker_bin, "ps", "--format", "{{.Names}}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        fatal_error(f"docker ps failed: {result.stderr.strip()}")

    candidates = [
        name.strip()
        for name in result.stdout.splitlines()
        if name.strip()
        and (service_name in name or "kali" in name.lower() or "attacker" in name.lower())
    ]
    if not candidates:
        message = (
            f"Could not find a running Kali attacker container matching '{service_name}'.\n"
            "Please ensure the Kali attacker service is running, then re-run this script.\n"
            f"Example: cd /app && {docker_bin} compose -f /app/docker-compose.yml up -d {service_name}"
        )
        fatal_error(message)

    found = candidates[0]
    if verbose:
        print(f"resolved attacker container to '{found}'")
    return found


def run_nmap_scan(
    docker_bin: str,
    target_container: str,
    scan_cidr: str,
    round_index: int,
    verbose: bool,
) -> None:
    """Run nmap TCP SYN scan to generate bidirectional TCP traffic visible to argus.
    
    -sS: TCP SYN scan (half-open scan)
    -F: Fast scan (only common ports)
    -Pn: Assume hosts are up (skip ping phase)
    """
    cmd = [docker_bin, "exec", target_container, "nmap", "-sS", "-F", "-Pn", scan_cidr]
    if verbose:
        print(f"[scan {round_index}] running: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"nmap scan round {round_index} failed ({result.returncode}): {result.stderr.strip()}"
        )
    if verbose:
        print(f"[scan {round_index}] completed: {len(result.stdout.splitlines())} hosts discovered")


def capture_dataset(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_file = output_path.open("w", encoding="utf-8")
    numeric_keys: list[str] | None = None
    target_container = resolve_running_container(
        args.docker_bin,
        args.kali_container,
        args.verbose,
    )
    discovered_ips, discovered_macs, discovered_subnet = discover_attacker_endpoints(
        args.docker_bin,
        target_container,
        args.verbose,
    )
    
    # Use provided scan CIDR or auto-detect from attacker's network
    scan_cidr = args.scan_cidr
    if not scan_cidr:
        if not discovered_subnet:
            fatal_error(
                "Unable to auto-detect target network from attacker container. "
                "Provide --scan-cidr explicitly."
            )
        scan_cidr = discovered_subnet
        if args.verbose:
            print(f"using auto-detected scan CIDR from attacker network: {scan_cidr}")

    # Filter discovered IPs to only those on the scan network, since a
    # multi-homed attacker has IPs on multiple networks (e.g. Docker
    # bridge + SCADA management).  Only IPs on the scan network are valid
    # attack sources for flow labeling.
    if scan_cidr:
        scan_net = ipaddress.ip_network(scan_cidr, strict=False)
        discovered_ips = [ip for ip in discovered_ips if ipaddress.ip_address(ip) in scan_net]

    attack_ips = [args.attack_ip] if args.attack_ip else discovered_ips
    attack_networks = parse_attack_targets(attack_ips, args.attack_cidr)
    attack_macs = (
        parse_attack_macs(args.attack_mac) if args.attack_mac else discovered_macs
    )
    if not attack_networks and not attack_macs:
        fatal_error(
            "Unable to determine attacker IP or MAC for labeling. "
            "Provide --attack-ip, --attack-mac, or ensure the attacker container has a reachable network address."
        )
    if args.verbose:
        print("effective attacker endpoints:")
        print(f"  IPs: {attack_ips}")
        print(f"  MACs: {sorted(attack_macs)}")
        print(f"  Target network: {scan_cidr}")

    flow_count = 0
    attack_count = 0
    normal_count = 0

    phase = PhaseTracker()
    stop_event = threading.Event()

    def scan_thread() -> None:
        """Run nmap scans from Kali attacker."""
        try:
            time.sleep(args.normal_duration)
            phase.set("cooldown")
            if args.verbose:
                print(f"normal capture complete, waiting {args.initial_cooldown}s before attack scans")
            time.sleep(args.initial_cooldown)

            target_container = resolve_running_container(
                args.docker_bin,
                args.kali_container,
                args.verbose,
            )

            # Configure nmap scan attacks
            attacks = [
                {
                    "name": "nmap_scan",
                    "cmd": [args.docker_bin, "exec", target_container, "nmap", "-sS", "-F", "-Pn", scan_cidr],
                    "count": args.scan_rounds,
                    "interval": args.scan_cooldown,
                }
            ]

            for attack in attacks:
                for round_index in range(1, attack["count"] + 1):
                    phase.set("attack")
                    if args.verbose:
                        print(f"[{attack['name']} {round_index}] running: {' '.join(attack['cmd'])}")
                    
                    result = subprocess.run(attack["cmd"], capture_output=True, text=True)
                    if result.returncode != 0:
                        raise RuntimeError(
                            f"{attack['name']} round {round_index} failed ({result.returncode}): {result.stderr.strip()}"
                        )

                    if round_index < attack["count"]:
                        phase.set("round_cooldown")
                        if args.verbose:
                            print(f"{attack['name']} {round_index} complete, waiting {attack['interval']}s before next round")
                        time.sleep(attack["interval"])

            phase.set("done")
        except Exception as exc:
            fatal_error(f"scan thread failed: {exc}")
        finally:
            stop_event.set()


    scanner = threading.Thread(target=scan_thread, daemon=True)
    scanner.start()

    if args.verbose:
        print(
            f"starting data collection: normal={args.normal_duration}s, "
            f"initial_cooldown={args.initial_cooldown}s, scans={args.scan_rounds}, "
            f"scan_cooldown={args.scan_cooldown}s, attack_ip={args.attack_ip}, "
            f"attack_mac={args.attack_mac}, output={output_path}"
        )

    try:
        # Capture all traffic on the interface
        for flow in iter_flows_from_interface_subprocess(args.interface, stop_event):
            current_phase = phase.get()
            if current_phase == "done":
                break
            if current_phase not in {"normal", "attack"}:
                continue

            record = flow_to_dict(flow)
            if numeric_keys is None:
                numeric_keys = extract_numeric_keys([record])

            is_attack = is_attack_flow(record, attack_networks, attack_macs)
            label = args.attack_label if is_attack else args.normal_label
            full_record = normalize_flow_record(record, numeric_keys)
            full_record[args.label_column] = label
            full_record["phase"] = current_phase
            full_record["capture_ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            write_record_jsonl(output_file, full_record)

            flow_count += 1
            if is_attack:
                attack_count += 1
            else:
                normal_count += 1

            if args.verbose and flow_count % 50 == 0:
                print(f"captured {flow_count} flows (attack={attack_count}, normal={normal_count})")

    except KeyboardInterrupt:
        print("capture interrupted by user", file=sys.stderr)
    finally:
        output_file.close()

    if args.verbose:
        print(
            f"capture finished: {flow_count} total flows, attack={attack_count}, normal={normal_count}"
        )
    return 0


def main() -> int:
    args = parse_args()
    return capture_dataset(args)


if __name__ == "__main__":
    raise SystemExit(main())
