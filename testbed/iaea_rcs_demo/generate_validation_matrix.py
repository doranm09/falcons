#!/usr/bin/env python3
from __future__ import annotations

import csv
import ipaddress
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COMPOSE_PATH = ROOT / "docker-compose.yml"
README_PATH = ROOT / "README.md"
MATRIX_MD_PATH = ROOT / "validation_matrix.md"
MATRIX_CSV_PATH = ROOT / "validation_matrix.csv"

README_SUMMARY_BEGIN = "<!-- BEGIN GENERATED VALIDATION SUMMARY -->"
README_SUMMARY_END = "<!-- END GENERATED VALIDATION SUMMARY -->"

NETWORK_LABELS = {
    "l4_net": "Layer 4",
    "l3_net": "Layer 3",
    "l2_net": "Layer 2",
    "l1_main": "Layer 1 (main PLC segment)",
    "l1_backup": "Layer 1 (backup PLC segment)",
    "p13_net": "Layer 0 (main cell)",
    "p23_net": "Layer 0 (backup cell)",
    "mgmt13_net": "Layer 1 management (main)",
    "mgmt23_net": "Layer 1 management (backup)",
}

NETWORK_ORDER = {
    "l4_net": 0,
    "l3_net": 1,
    "l2_net": 2,
    "l1_main": 3,
    "l1_backup": 3,
    "mgmt13_net": 4,
    "mgmt23_net": 4,
    "p13_net": 5,
    "p23_net": 5,
}

FIREWALL_BOUNDARY_LABELS = {
    "firewall-2": "Layer 4 / Layer 3",
    "firewall-1": "Layer 3 / Layer 2",
    "firewall-0": "Layer 2 / Layer 1",
    "firewall-main-cell": "Layer 1 / Layer 0 (main cell)",
    "firewall-backup-cell": "Layer 1 / Layer 0 (backup cell)",
}


@dataclass(frozen=True)
class Route:
    network: ipaddress.IPv4Network
    via: ipaddress.IPv4Address


@dataclass(frozen=True)
class Interface:
    service: str
    network: str
    ip: ipaddress.IPv4Address


@dataclass
class Node:
    name: str
    kind: str
    display_name: str
    role: str
    service_ports: list[int]
    networks: dict[str, ipaddress.IPv4Address]
    routes: list[Route]
    published_ports: list[tuple[int, int]]
    allow_rules: set[tuple[str, str, int]]


def load_compose() -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        pass
    else:
        return yaml.safe_load(COMPOSE_PATH.read_text())

    command = [
        "docker",
        "compose",
        "-f",
        COMPOSE_PATH.name,
        "config",
        "--format",
        "json",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit(
            "PyYAML is unavailable and `docker compose config --format json` "
            "could not be executed."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.stderr.strip() or "failed to load compose config") from exc
    return json.loads(completed.stdout)


def normalize_environment(raw_environment: object) -> dict[str, str]:
    if isinstance(raw_environment, dict):
        return {str(key): str(value) for key, value in raw_environment.items()}

    environment: dict[str, str] = {}
    for item in raw_environment or []:
        key, _, value = str(item).partition("=")
        environment[key] = value
    return environment


def parse_ports_csv(value: str) -> list[int]:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            ports.append(int(item))
    return sorted(set(ports))


def parse_routes(value: str) -> list[Route]:
    routes: list[Route] = []
    for item in value.split(";"):
        item = item.strip()
        if not item:
            continue
        network_text, separator, next_hop_text = item.partition(" via ")
        if not separator:
            raise ValueError(f"invalid route spec: {item}")
        routes.append(
            Route(
                network=ipaddress.ip_network(network_text.strip()),
                via=ipaddress.ip_address(next_hop_text.strip()),
            )
        )
    return routes


def parse_allow_rules(environment: dict[str, str]) -> set[tuple[str, str, int]]:
    rules: set[tuple[str, str, int]] = set()

    def load(specs: str, bidirectional: bool) -> None:
        for spec in specs.split(";"):
            spec = spec.strip()
            if not spec:
                continue
            src, dst, ports_csv = [part.strip() for part in spec.split("|")]
            for port in parse_ports_csv(ports_csv):
                rules.add((src, dst, port))
                if bidirectional:
                    rules.add((dst, src, port))

    load(environment.get("ALLOW_TCP", ""), bidirectional=False)
    load(environment.get("ALLOW_BIDIR_TCP", ""), bidirectional=True)
    return rules


def parse_published_ports(raw_ports: object) -> list[tuple[int, int]]:
    published_ports: list[tuple[int, int]] = []
    for item in raw_ports or []:
        if isinstance(item, dict):
            published = item.get("published")
            target = item.get("target")
            if published is not None and target is not None:
                published_ports.append((int(published), int(target)))
            continue

        match = re.search(r"(?:(?:[^:]+):)?(\d+):(\d+)(?:/\w+)?$", str(item))
        if not match:
            raise ValueError(f"unsupported port mapping: {item}")
        published_ports.append((int(match.group(1)), int(match.group(2))))
    return sorted(published_ports)


def sort_networks(network_items: list[tuple[str, ipaddress.IPv4Address]]) -> list[tuple[str, ipaddress.IPv4Address]]:
    return sorted(
        network_items,
        key=lambda item: (NETWORK_ORDER.get(item[0], 99), item[0], int(item[1])),
    )


def build_inventory(compose: dict) -> tuple[dict[str, Node], dict[str, Interface], dict[str, ipaddress.IPv4Network]]:
    network_cidrs = {
        name: ipaddress.ip_network(config["ipam"]["config"][0]["subnet"])
        for name, config in compose["networks"].items()
    }

    nodes: dict[str, Node] = {}
    interfaces_by_ip: dict[str, Interface] = {}

    for service_name, service_config in compose["services"].items():
        environment = normalize_environment(service_config.get("environment", {}))
        networks: dict[str, ipaddress.IPv4Address] = {}
        raw_networks = service_config.get("networks", {})
        for network_name, network_config in raw_networks.items():
            if isinstance(network_config, dict) and network_config.get("ipv4_address"):
                ip_address = ipaddress.ip_address(network_config["ipv4_address"])
                networks[network_name] = ip_address
                interfaces_by_ip[str(ip_address)] = Interface(
                    service=service_name,
                    network=network_name,
                    ip=ip_address,
                )

        node = Node(
            name=service_name,
            kind="endpoint" if "DEVICE_NAME" in environment else "firewall",
            display_name=environment.get("DEVICE_NAME", environment.get("FIREWALL_NAME", service_name)),
            role=environment.get("DEVICE_ROLE", environment.get("FIREWALL_NAME", service_name)),
            service_ports=parse_ports_csv(environment.get("SERVICE_PORTS", "")),
            networks=networks,
            routes=parse_routes(environment.get("STATIC_ROUTES", "")),
            published_ports=parse_published_ports(service_config.get("ports", [])),
            allow_rules=parse_allow_rules(environment),
        )
        nodes[service_name] = node

    return nodes, interfaces_by_ip, network_cidrs


def service_sort_key(node: Node) -> tuple[int, str]:
    first_network = min(node.networks, key=lambda name: (NETWORK_ORDER.get(name, 99), name))
    return NETWORK_ORDER.get(first_network, 99), node.name


def interface_sort_key(interface: Interface) -> tuple[int, str, int]:
    return NETWORK_ORDER.get(interface.network, 99), interface.network, int(interface.ip)


def matching_direct_network(
    node: Node,
    network_cidrs: dict[str, ipaddress.IPv4Network],
    target_ip: ipaddress.IPv4Address,
) -> str | None:
    for network_name, interface_ip in sort_networks(list(node.networks.items())):
        del interface_ip
        if target_ip in network_cidrs[network_name]:
            return network_name
    return None


def best_route(node: Node, target_ip: ipaddress.IPv4Address) -> Route | None:
    matches = [route for route in node.routes if target_ip in route.network]
    if not matches:
        return None
    return max(matches, key=lambda route: route.network.prefixlen)


def resolve_path(
    source: Node,
    destination: Interface,
    nodes: dict[str, Node],
    interfaces_by_ip: dict[str, Interface],
    network_cidrs: dict[str, ipaddress.IPv4Network],
) -> dict[str, object]:
    target_ip = destination.ip
    current = source
    visited: set[str] = set()
    path = [source.name]
    source_network: str | None = None

    while True:
        direct_network = matching_direct_network(current, network_cidrs, target_ip)
        if direct_network is not None:
            if source_network is None:
                source_network = direct_network
            return {
                "path": path + [destination.service],
                "source_network": source_network,
                "source_ip": str(source.networks[source_network]),
            }

        if current.name in visited:
            return {
                "path": None,
                "source_network": source_network,
                "source_ip": None,
                "failure": "routing loop",
            }
        visited.add(current.name)

        route = best_route(current, target_ip)
        if route is None:
            return {
                "path": None,
                "source_network": source_network,
                "source_ip": None,
                "failure": "no route",
            }

        next_hop = interfaces_by_ip.get(str(route.via))
        if next_hop is None:
            return {
                "path": None,
                "source_network": source_network,
                "source_ip": None,
                "failure": f"unknown next hop {route.via}",
            }

        outgoing_network = matching_direct_network(current, network_cidrs, route.via)
        if outgoing_network is None:
            return {
                "path": None,
                "source_network": source_network,
                "source_ip": None,
                "failure": f"next hop {route.via} is not directly connected",
            }

        if source_network is None:
            source_network = outgoing_network

        path.append(next_hop.service)
        current = nodes[next_hop.service]


def layer_under_test_for_unreachable(source: Node, destination: Interface) -> str:
    source_network = min(source.networks, key=lambda name: (NETWORK_ORDER.get(name, 99), name))
    return f"{NETWORK_LABELS[source_network]} -> {NETWORK_LABELS[destination.network]} isolation"


def render_interface_label(interface: Interface) -> str:
    return f"{interface.service} ({interface.network})"


def build_matrix_rows(
    nodes: dict[str, Node],
    interfaces_by_ip: dict[str, Interface],
    network_cidrs: dict[str, ipaddress.IPv4Network],
) -> list[dict[str, str]]:
    endpoint_names = [
        node.name
        for node in sorted(
            (node for node in nodes.values() if node.kind == "endpoint"),
            key=service_sort_key,
        )
    ]

    rows: list[dict[str, str]] = []
    for source_name in endpoint_names:
        source = nodes[source_name]
        destinations = [
            interface
            for interface in sorted(interfaces_by_ip.values(), key=interface_sort_key)
            if nodes[interface.service].kind == "endpoint" and interface.service != source_name
        ]

        for destination in destinations:
            destination_node = nodes[destination.service]
            for port in destination_node.service_ports:
                route = resolve_path(source, destination, nodes, interfaces_by_ip, network_cidrs)
                path = route["path"]
                if not path:
                    layer_under_test = layer_under_test_for_unreachable(source, destination)
                    expected = f"blocked ({route['failure']})"
                    command = f"expect_blocked_port {source_name} {destination.ip} {port}"
                else:
                    traversed_firewalls = [
                        nodes[name]
                        for name in path[1:-1]
                        if nodes[name].kind == "firewall"
                    ]
                    source_ip = str(route["source_ip"])
                    blocking_firewall = next(
                        (
                            firewall
                            for firewall in traversed_firewalls
                            if (source_ip, str(destination.ip), port) not in firewall.allow_rules
                        ),
                        None,
                    )
                    if traversed_firewalls:
                        layer_under_test = " + ".join(
                            FIREWALL_BOUNDARY_LABELS[firewall.name]
                            for firewall in traversed_firewalls
                        )
                    else:
                        layer_under_test = f"Intra-zone: {NETWORK_LABELS[destination.network]}"

                    if blocking_firewall is None:
                        expected = "allow"
                        command = f"probe_port {source_name} {destination.ip} {port}"
                    else:
                        expected = f"blocked ({blocking_firewall.name})"
                        command = f"expect_blocked_port {source_name} {destination.ip} {port}"

                rows.append(
                    {
                        "source": source_name,
                        "destination": destination.service,
                        "destination_interface": render_interface_label(destination),
                        "destination_ip": str(destination.ip),
                        "port": str(port),
                        "expected": expected,
                        "layer_under_test": layer_under_test,
                        "command": command,
                        "path": " -> ".join(path) if path else route["failure"],
                    }
                )

    return rows


def build_route_isolation_rows() -> list[dict[str, str]]:
    return [
        {
            "check": "metasploit route table",
            "command": "expect_no_l1_l0_or_mgmt_routes metasploit",
            "expected": "no matching routes present",
            "policy": "Layer 4 has no routes into Layer 1, Layer 0, or management nets",
        },
        {
            "check": "historian route table",
            "command": "expect_no_l0_or_mgmt_routes historian",
            "expected": "no matching routes present",
            "policy": "Layer 3 historian may route to Layer 2 and Layer 1 OPC endpoints, but it still has no direct routes into Layer 0 or the management nets",
        },
        {
            "check": "hmi route table",
            "command": "expect_no_l0_or_mgmt_routes hmi",
            "expected": "no matching routes present",
            "policy": "Layer 2 operator access does not route directly into Layer 0 or management nets",
        },
        {
            "check": "engineer-ws route table",
            "command": "expect_no_l0_or_mgmt_routes engineer-ws",
            "expected": "no matching routes present",
            "policy": "Layer 2 engineering access does not route directly into Layer 0 or management nets",
        },
        {
            "check": "l2-jump route table",
            "command": "expect_no_l1_l0_or_mgmt_routes l2-jump",
            "expected": "no matching routes present",
            "policy": "The Layer 2 jumpbox does not have PLC, process, or management routes",
        },
    ]


def build_host_rows(nodes: dict[str, Node]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for node in sorted(
        (node for node in nodes.values() if node.kind == "endpoint" and node.published_ports),
        key=service_sort_key,
    ):
        for published_port, target_port in node.published_ports:
            rows.append(
                {
                    "host_port": str(published_port),
                    "destination": node.name,
                    "target_port": str(target_port),
                    "command": f"curl -fsS --max-time 3 http://127.0.0.1:{published_port}/",
                    "expected": (
                        f'JSON with `"device": "{node.display_name}"` and '
                        f'`"local_port": {target_port}`'
                    ),
                }
            )
    return rows


def markdown_table(rows: list[dict[str, str]], columns: list[str], headers: list[str]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        values = [str(row[column]).replace("|", "\\|") for column in columns]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def write_matrix_csv(rows: list[dict[str, str]]) -> None:
    columns = [
        "source",
        "destination",
        "destination_interface",
        "destination_ip",
        "port",
        "expected",
        "layer_under_test",
        "command",
        "path",
    ]
    with MATRIX_CSV_PATH.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_matrix_markdown(
    matrix_rows: list[dict[str, str]],
    route_rows: list[dict[str, str]],
    host_rows: list[dict[str, str]],
) -> None:
    allow_count = sum(1 for row in matrix_rows if row["expected"] == "allow")
    blocked_count = len(matrix_rows) - allow_count
    layer_counter = Counter(row["layer_under_test"] for row in matrix_rows)

    lines = [
        "# Validation Matrix",
        "",
        "Generated from `docker-compose.yml` by `generate_validation_matrix.py`. Do not hand-edit this file.",
        "",
        "## Summary",
        "",
        f"- Service/interface permutations: `{len(matrix_rows)}`",
        f"- Expected allow results: `{allow_count}`",
        f"- Expected blocked results: `{blocked_count}`",
        f"- Route-isolation checks: `{len(route_rows)}`",
        f"- Host published-port checks: `{len(host_rows)}`",
        "",
        "Boundary distribution:",
    ]
    for label, count in sorted(layer_counter.items()):
        lines.append(f"- `{label}`: `{count}`")

    lines.extend(
        [
            "",
            "## Service Reachability Matrix",
            "",
            markdown_table(
                matrix_rows,
                [
                    "source",
                    "destination_interface",
                    "destination_ip",
                    "port",
                    "expected",
                    "layer_under_test",
                    "command",
                ],
                [
                    "Source",
                    "Destination",
                    "Probe IP",
                    "Port",
                    "Expected",
                    "Layer Under Test",
                    "Command",
                ],
            ),
            "",
            "## Route Isolation Checks",
            "",
            markdown_table(
                route_rows,
                ["check", "command", "expected", "policy"],
                ["Check", "Command", "Expected", "Policy confirmed"],
            ),
            "",
            "## Host Published Ports",
            "",
            markdown_table(
                host_rows,
                ["host_port", "destination", "target_port", "command", "expected"],
                ["Host Port", "Destination", "Container Port", "Command", "Expected"],
            ),
            "",
        ]
    )
    MATRIX_MD_PATH.write_text("\n".join(lines))


def update_readme_summary(
    matrix_rows: list[dict[str, str]],
    route_rows: list[dict[str, str]],
    host_rows: list[dict[str, str]],
) -> None:
    allow_count = sum(1 for row in matrix_rows if row["expected"] == "allow")
    blocked_count = len(matrix_rows) - allow_count
    summary = "\n".join(
        [
            README_SUMMARY_BEGIN,
            "Generated from [`docker-compose.yml`](./docker-compose.yml) by "
            "[`generate_validation_matrix.py`](./generate_validation_matrix.py).",
            "",
            f"- Full matrix: [`validation_matrix.md`](./validation_matrix.md)",
            f"- CSV export: [`validation_matrix.csv`](./validation_matrix.csv)",
            f"- Service/interface permutations: `{len(matrix_rows)}` total, "
            f"`{allow_count}` allow, `{blocked_count}` blocked",
            f"- Route-isolation checks: `{len(route_rows)}`",
            f"- Host published-port checks: `{len(host_rows)}`",
            README_SUMMARY_END,
        ]
    )

    readme_text = README_PATH.read_text()
    pattern = re.compile(
        rf"{re.escape(README_SUMMARY_BEGIN)}.*?{re.escape(README_SUMMARY_END)}",
        re.DOTALL,
    )
    if not pattern.search(readme_text):
        raise SystemExit("README validation summary markers are missing")
    README_PATH.write_text(pattern.sub(summary, readme_text, count=1))


def main() -> None:
    compose = load_compose()
    nodes, interfaces_by_ip, network_cidrs = build_inventory(compose)
    matrix_rows = build_matrix_rows(nodes, interfaces_by_ip, network_cidrs)
    route_rows = build_route_isolation_rows()
    host_rows = build_host_rows(nodes)

    write_matrix_csv(matrix_rows)
    write_matrix_markdown(matrix_rows, route_rows, host_rows)
    update_readme_summary(matrix_rows, route_rows, host_rows)


if __name__ == "__main__":
    main()
