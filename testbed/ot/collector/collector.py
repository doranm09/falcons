#!/usr/bin/env python3
import json
import os
import time
from pathlib import Path
from urllib.request import urlopen
import hashlib

COLLECTOR_ZONE = os.getenv("COLLECTOR_ZONE", "L3")
INVENTORY_PATH = Path(os.getenv("INVENTORY_PATH", "/workspace/inventory.json"))
FIXED_TIME = os.getenv("FIXED_TIME", "2026-01-25T00:00:00Z")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
ONE_SHOT = os.getenv("ONE_SHOT", "0") == "1"

zone_slug = COLLECTOR_ZONE.replace("/", "-")
OUT_PATH = Path(os.getenv("OUT_PATH", f"/data/collectors/collector-{zone_slug}.json"))


def fetch_evidence(asset):
    url = f"http://{asset['ip']}:{asset['port']}/evidence"
    try:
        with urlopen(url, timeout=0.4) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def collect_once():
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    assets = [a for a in inventory["assets"] if a.get("zone") == COLLECTOR_ZONE]
    results = []
    for asset in assets:
        evidence = fetch_evidence(asset)
        results.append({
            "name": asset["name"],
            "zone": asset["zone"],
            "ip": asset["ip"],
            "port": asset["port"],
            "reachable": evidence is not None,
            "evidence": evidence,
        })

    prev_hash = None
    if OUT_PATH.exists():
        try:
            prev = json.loads(OUT_PATH.read_text(encoding="utf-8"))
            prev_hash = prev.get("provenance", {}).get("payload_hash")
        except Exception:
            prev_hash = None

    payload = {
        "collector_zone": COLLECTOR_ZONE,
        "generated_at": FIXED_TIME,
        "time_source": "FIXED_TIME",
        "clock_skew_s": 0,
        "assets": results,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash = hashlib.sha256(canonical).hexdigest()
    payload["provenance"] = {
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main():
    while True:
        collect_once()
        if ONE_SHOT:
            break
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
