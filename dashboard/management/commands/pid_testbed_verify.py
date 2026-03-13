from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Verify PID testbed reachability using scanner outputs."

    def add_arguments(self, parser):
        parser.add_argument(
            "--inventory",
            default="testbed/ot/inventory.json",
            help="Path to PID inventory.json (default: testbed/ot/inventory.json)",
        )
        parser.add_argument(
            "--scans-dir",
            default="testbed/ot/data/scans",
            help="Directory containing scanner outputs (default: testbed/ot/data/scans)",
        )

    def handle(self, *args, **options):
        inventory_path = Path(options["inventory"]).expanduser()
        scans_dir = Path(options["scans_dir"]).expanduser()

        if not inventory_path.exists():
            raise SystemExit(f"Inventory not found: {inventory_path}")
        if not scans_dir.exists():
            raise SystemExit(f"Scans directory not found: {scans_dir}")

        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        assets = inventory.get("assets", [])
        if not assets:
            raise SystemExit("Inventory has no assets")

        scan_results = {}
        for scan_file in scans_dir.glob("scan-*.json"):
            try:
                payload = json.loads(scan_file.read_text(encoding="utf-8"))
                zone = payload.get("scan_zone")
                if zone:
                    scan_results[zone] = payload.get("assets", [])
            except json.JSONDecodeError:
                continue

        missing = []
        unreachable = []
        for asset in assets:
            zone = asset.get("zone")
            ip = asset.get("ip")
            name = asset.get("name")
            zone_assets = scan_results.get(zone)
            if not zone_assets:
                missing.append({"zone": zone, "name": name, "ip": ip, "reason": "no_scan"})
                continue
            match = next((entry for entry in zone_assets if entry.get("ip") == ip), None)
            if not match:
                missing.append({"zone": zone, "name": name, "ip": ip, "reason": "not_reported"})
                continue
            if not match.get("reachable", False):
                unreachable.append({"zone": zone, "name": name, "ip": ip})

        report = {
            "assets": len(assets),
            "missing": missing,
            "unreachable": unreachable,
        }

        if missing or unreachable:
            self.stdout.write(json.dumps(report, indent=2))
            raise SystemExit("PID testbed verification failed")

        self.stdout.write(self.style.SUCCESS("PID testbed verification passed"))
