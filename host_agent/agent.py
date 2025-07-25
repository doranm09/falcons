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
import datetime
import json
from sbom.os_sbom import collect_linux_packages

SERVER_URL = "http://localhost:8000"
AGENT_ID = str(uuid.getnode())

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
        if snic.family == psutil.AF_LINK:
            return snic.address
    return None

def get_processes():
    return [
        {"pid": p.info['pid'], "name": p.info['name']}
        for p in psutil.process_iter(attrs=['pid', 'name'])
    ]

def send_heartbeat():
    data = get_system_info()
    try:
        res = requests.post(f"{SERVER_URL}/agent/report/", json=data)
        print(f"[heartbeat] status={res.status_code}")
    except Exception as e:
        print(f"[heartbeat] error: {e}")

def poll_for_commands():
    try:
        res = requests.get(f"{SERVER_URL}/agent/commands/?agent_id={AGENT_ID}")
        cmds = res.json().get("commands", [])
        for cmd in cmds:
            handle_command(cmd)
    except Exception as e:
        print(f"[commands] polling error: {e}")

def handle_command(cmd):
    cmd_id = cmd.get("id")
    action = cmd.get("action")

    print(f"[command] received: {cmd}")

    if action == "ping":
        result = subprocess.run(["ping", "-c", "2", "8.8.8.8"], capture_output=True, text=True)
        return_output(cmd_id, result.stdout)
    elif action == "scan":
        # Placeholder: run scan tool
        return_output(cmd_id, "scan complete (stub)")
    else:
        return_output(cmd_id, f"Unknown action: {action}")

def return_output(cmd_id, output):
    try:
        requests.post(f"{SERVER_URL}/agent/command_result/", json={
            "agent_id": AGENT_ID,
            "command_id": cmd_id,
            "output": output
        })
    except Exception as e:
        print(f"[command_result] failed: {e}")

def main_loop():
    while True:
        send_heartbeat()
        poll_for_commands()
        time.sleep(30)

if __name__ == "__main__":
    
    # parse commands
    parser = argparse.ArgumentParser(description="Host Agent CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("run", help="Run persistent agent loop")
    subparsers.add_parser("heartbeat", help="send a single heartbeat")
    subparsers.add_parser("poll", help="Poll once for commands")
    subparsers.add_parser("info", help="Print system info")
    subparsers.add_parser("sbom", help="Collect installed package list (SBOM)")

    args = parser.parse_args()

    # process command
    if args.command == "run":
        main_loop()
    elif args.command == "heartbeat":
        send_heartbeat()
    elif args.command == "info":
        print(json.dumps(get_system_info(), indent=2))
    elif args.command == "sbom":
        packages = collect_linux_packages()
        print(json.dumps(packages, indent=2))
    else:
        parser.print_help()
