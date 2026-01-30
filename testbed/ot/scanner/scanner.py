#!/usr/bin/env python3
import json
import os
import socket
import time
from pathlib import Path

SCAN_ZONE = os.getenv("SCAN_ZONE", "L3.5")
INVENTORY_PATH = Path(os.getenv("INVENTORY_PATH", "/workspace/inventory.json"))
FIXED_TIME = os.getenv("FIXED_TIME", "2026-01-25T00:00:00Z")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
ONE_SHOT = os.getenv("ONE_SHOT", "0") == "1"

zone_slug = SCAN_ZONE.replace("/", "-")
OUT_PATH = Path(os.getenv("OUT_PATH", f"/data/scans/scan-{zone_slug}.json"))


def tcp_check(host, port, timeout=0.3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        sock.close()


def scan_once():
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    assets = [a for a in inventory["assets"] if a.get("zone") == SCAN_ZONE]
    results = []
    for asset in assets:
        reachable = tcp_check(asset["ip"], asset["port"])
        results.append({
            "name": asset["name"],
            "zone": asset["zone"],
            "ip": asset["ip"],
            "port": asset["port"],
            "reachable": reachable,
        })

    payload = {
        "scan_zone": SCAN_ZONE,
        "generated_at": FIXED_TIME,
        "time_source": "FIXED_TIME",
        "clock_skew_s": 0,
        "assets": results,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main():
    while True:
        scan_once()
        if ONE_SHOT:
            break
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
