import os
import platform
import socket
import uuid
import psutil
import requests
import json
import time
import threading
import subprocess
import argparse
from datetime import datetime
from sbom.os_sbom import collect_linux_packages, collect_packages, generate_cyclonedx_sbom
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP
import heapq

# ---- Config (overridden at runtime from --url / env) ----
SERVER_URL = "http://localhost:8000"   # will be reassigned in __main__
AGENT_ID = str(uuid.getnode())
neighbor_table = {}
tcp_syn_times = {}
network_graph = {}

REQ_TIMEOUT = (3.0, 10.0)  # (connect, read) seconds


# ---- HTTP helper ----
def http_post_json(url, payload, headers=None):
    try:
        h = {
            "Content-Type": "application/json",
            "User-Agent": f"agent/{AGENT_ID}"
        }
        if headers:
            h.update(headers)
        res = requests.post(url, json=payload, headers=h, timeout=REQ_TIMEOUT)
        return res
    except Exception as e:
        print(f"[http] POST {url} failed: {e}")
        return None


def http_get_json(url, headers=None):
    try:
        h = {"User-Agent": f"agent/{AGENT_ID}"}
        if headers:
            h.update(headers)
        res = requests.get(url, headers=h, timeout=REQ_TIMEOUT)
        return res
    except Exception as e:
        print(f"[http] GET {url} failed: {e}")
        return None


# ---- System info ----
def get_system_info():
    return {
        "agent_id": AGENT_ID,
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "cpu_count": psutil.cpu_count(),
        "memory_total": psutil.virtual_memory().total,
        "interfaces": get_interfaces(),
        "processes": get_processes()
    }


def get_interfaces():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces.append({
                    "name": iface,
                    "ip": addr.address,
                    "mac": get_mac_address(iface)
                })
    return interfaces


def get_mac_address(iface):
    for snic in psutil.net_if_addrs().get(iface, []):
        if getattr(snic, "family", None) == psutil.AF_LINK or str(getattr(snic, "family", "")) == "AddressFamily.AF_PACKET":
            return snic.address
    return None


def get_processes():
    return [
        {"pid": p.info['pid'], "name": p.info['name']}
        for p in psutil.process_iter(attrs=['pid', 'name'])
    ]


# ---- Agent <-> Server ----
def send_heartbeat():
    data = get_system_info()
    url = f"{SERVER_URL.rstrip('/')}/agent/report/"
    res = http_post_json(url, data)
    if res is None:
        print("[heartbeat] error (request failed)")
    else:
        print(f"[heartbeat] status={res.status_code}")


def poll_for_commands():
    url = f"{SERVER_URL.rstrip('/')}/agent/commands/?agent_id={AGENT_ID}"
    res = http_get_json(url)
    if res is None:
        print("[commands] polling error (request failed)")
        return
    try:
        cmds = res.json().get("commands", [])
    except Exception as e:
        print(f"[commands] bad JSON: {e}")
        cmds = []
    for cmd in cmds:
        handle_command(cmd)


def handle_command(cmd):
    cmd_id = cmd.get("id")
    action = cmd.get("action")

    print(f"[command] received: {cmd}")

    if action == "ping":
        # Linux ping; adjust for Windows if needed
        result = subprocess.run(["ping", "-c", "2", "8.8.8.8"], capture_output=True, text=True)
        return_output(cmd_id, result.stdout)
    elif action == "scan":
        return_output(cmd_id, "scan complete (stub)")
    else:
        return_output(cmd_id, f"Unknown action: {action}")


def return_output(cmd_id, output):
    url = f"{SERVER_URL.rstrip('/')}/agent/command_result/"
    payload = {
        "agent_id": AGENT_ID,
        "command_id": cmd_id,
        "output": output
    }
    res = http_post_json(url, payload)
    if res is None:
        print("[command_result] failed (request failed)")


# ---- SBOM ----
def post_sbom_to_server(sbom_data, server_url=None, agent_id="unknown"):
    """
    server_url:
      - If None, posts to f"{SERVER_URL}/sbom"
      - Otherwise, post to the given absolute URL.
    """
    target = server_url or f"{SERVER_URL.rstrip('/')}/sbom"
    headers = {
        "X-Agent-ID": agent_id,
        "X-Timestamp": datetime.utcnow().isoformat() + "Z"
    }
    res = http_post_json(target, sbom_data, headers=headers)
    if res is None:
        print("[sbom] Failed to post (request failed)")
    else:
        print(f"[sbom] POST status: {res.status_code}")
        if res.status_code != 200:
            print(f"[sbom] Error: {res.text}")


# ---- Graph / latency ----
def update_graph_latency(src, dst, latency):
    network_graph.setdefault(src, {})[dst] = latency
    network_graph.setdefault(dst, {})[src] = latency


def dijkstra(graph, start, end):
    queue = [(0, start, [])]
    visited = set()
    while queue:
        cost, node, path = heapq.heappop(queue)
        if node in visited:
            continue
        visited.add(node)
        path = path + [node]
        if node == end:
            return (cost, path)
        for neighbor, weight in graph.get(node, {}).items():
            if neighbor not in visited:
                heapq.heappush(queue, (cost + weight, neighbor, path))
    return (float("inf"), [])


# ---- Packet capture ----
def packet_callback(pkt):
    info = {
        "timestamp": datetime.now().isoformat(),
        "proto": "Unknown",
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
    }

    now = datetime.utcnow()

    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(IP):
        info["proto"] = "IP"
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst

        if pkt.haslayer(TCP):
            info["proto"] = "TCP"
            tcp = pkt[TCP]
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            key = (info["src_ip"], info["dst_ip"], info["dst_port"])
            flags = getattr(tcp, "flags", "")
            # Use bit checks to be robust:
            # SYN = 0x02, ACK = 0x10
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            if syn and not ack:  # SYN
                tcp_syn_times[key] = now
            elif syn and ack:    # SYN-ACK
                reverse_key = (info["dst_ip"], info["src_ip"], tcp.sport)
                if reverse_key in tcp_syn_times:
                    delta = (now - tcp_syn_times.pop(reverse_key)).total_seconds() * 1000
                    print(f"[latency] {reverse_key[0]} -> {reverse_key[1]}: ~{delta:.2f} ms")
                    update_graph_latency(reverse_key[0], reverse_key[1], delta)

        elif pkt.haslayer(UDP):
            info["proto"] = "UDP"
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            info["proto"] = "ICMP"

    elif pkt.haslayer(ARP):
        info["proto"] = "ARP"
        info["src_ip"] = pkt[ARP].psrc
        info["dst_ip"] = pkt[ARP].pdst

    print(f"[sniff] {info['timestamp']} {info['proto']} {info['src_mac']} -> {info['dst_mac']} | "
          f"{info['src_ip']}:{info['src_port']} -> {info['dst_ip']}:{info['dst_port']}")

    key = (info["src_ip"], info["src_mac"])
    if key not in neighbor_table:
        neighbor_table[key] = {
            "first_seen": info["timestamp"],
            "proto": info["proto"]
        }
        print(f"[neighbor] new: {info['src_ip']} / {info['src_mac']} via {info['proto']}")

    # Auto-path calculation from new node
    if info["src_ip"] in network_graph:
        for target in network_graph:
            if target != info["src_ip"]:
                cost, path = dijkstra(network_graph, info["src_ip"], target)
                if path:
                    print(f"[autopath] {info['src_ip']} -> {target} ~{cost:.2f} ms via: {' -> '.join(path)}")


def sniff_interface(interface):
    print(f"[sniff] Starting sniff on {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)


# ---- Interactive path calc ----
def run_dijkstra_interactive():
    print("\n[graph] Known nodes:")
    for node in network_graph:
        print(f" - {node}")
    start = input("Enter start IP: ").strip()
    end = input("Enter end IP: ").strip()
    cost, path = dijkstra(network_graph, start, end)
    if path:
        print(f"[path] {start} -> {end} in {cost:.2f} ms via: {' -> '.join(path)}")
    else:
        print(f"[path] No route found from {start} to {end}.")


# ---- Main loop ----
def main_loop():
    while True:
        send_heartbeat()
        poll_for_commands()
        time.sleep(30)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Host Agent CLI")
    parser.add_argument("--url", help="Base server URL for the dashboard API (e.g., http://server:8000)")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("run", help="Run persistent agent loop")
    subparsers.add_parser("heartbeat", help="Send a single heartbeat")
    subparsers.add_parser("poll", help="Poll once for commands")
    subparsers.add_parser("info", help="Print system info")
    sbom_parser = subparsers.add_parser("sbom", help="Collect installed package list (SBOM)")
    sbom_parser.add_argument("--output", "-o", help="Write SBOM to a file")
    sbom_parser.add_argument("--format", "-f", choices=["raw", "cyclonedx"], default="raw", help="SBOM output format")
    sbom_parser.add_argument("--sbom-url", help="Override SBOM POST URL (default: <server>/sbom)")
    sniff_parser = subparsers.add_parser("sniff", help="Sniff packets on interface")
    sniff_parser.add_argument("--interface", "-i", required=True, help="Interface to sniff on")
    subparsers.add_parser("path", help="Run Dijkstra to find shortest latency path interactively")

    args = parser.parse_args()

    # Resolve SERVER_URL: CLI → env → default
    cli_url = (args.url or "").strip()
    env_url = os.environ.get("AGENT_SERVER_URL", "").strip()
    if cli_url:
        SERVER_URL = cli_url
    elif env_url:
        SERVER_URL = env_url

    # Commands
    if args.command == "run":
        main_loop()
    elif args.command == "heartbeat":
        send_heartbeat()
    elif args.command == "poll":
        poll_for_commands()
    elif args.command == "info":
        print(json.dumps(get_system_info(), indent=2))
    elif args.command == "sbom":
        packages = collect_packages()
        sbom = generate_cyclonedx_sbom(packages) if args.format == "cyclonedx" else packages
        if args.output:
            with open(args.output, "w") as f:
                json.dump(sbom, f, indent=2)
            print(f"[sbom] SBOM written to {args.output}")
        else:
            print(json.dumps(sbom, indent=2))
        post_sbom_to_server(sbom_data=sbom, server_url=args.sbom_url, agent_id=AGENT_ID)
    elif args.command == "sniff":
        sniff_interface(args.interface)
    elif args.command == "path":
        run_dijkstra_interactive()
    else:
        parser.print_help()
