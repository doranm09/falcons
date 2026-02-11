from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from dashboard.models import Link, Node, NodeInterface, ScanRun
from dashboard.pid_system import load_sim_system_file, resolve_sim_system_path
from dashboard.pid_network import expected_cyber_nodes, summarize_expected_nodes, validate_expected_nodes
from dashboard.tasks import scan_network_task, nmap_discovery_task, launch_openvas_scan_task


class Command(BaseCommand):
    help = "Validate PID cyber nodes against discovered network inventory and optionally launch scans."

    def add_arguments(self, parser):
        parser.add_argument(
            "--source",
            default="auto",
            choices=["auto", "target", "latest"],
            help="sim_system source (auto, target, latest).",
        )
        parser.add_argument(
            "--sim-system",
            default=None,
            help="Optional explicit path to sim_system.json.",
        )
        parser.add_argument(
            "--scan-run-id",
            type=int,
            default=None,
            help="Only compare against nodes from this scan_run_id.",
        )
        parser.add_argument(
            "--scan",
            choices=["ping", "nmap"],
            default=None,
            help="Launch discovery scans for VLAN CIDRs (from PID).",
        )
        parser.add_argument(
            "--scan-sync",
            action="store_true",
            help="Run discovery scan tasks synchronously instead of Celery.",
        )
        parser.add_argument(
            "--openvas",
            action="store_true",
            help="Launch OpenVAS scans for VLAN CIDRs (from PID).",
        )
        parser.add_argument(
            "--create-twin",
            action="store_true",
            help="Create a scan run from the PID cyber nodes and links for digital twin generation.",
        )
        parser.add_argument(
            "--output",
            default=None,
            help="Optional output path for validation report JSON.",
        )

    def handle(self, *args, **options):
        sim_path = self._resolve_sim_system_path(options)
        sim_system = load_sim_system_file(sim_path)

        expected_nodes = expected_cyber_nodes(sim_system)
        summary = summarize_expected_nodes(expected_nodes)

        discovered_ips = self._load_discovered_ips(options.get("scan_run_id"))
        validation = validate_expected_nodes(expected_nodes, discovered_ips)

        scan_results = []
        if options.get("scan"):
            scan_results = self._launch_discovery_scans(summary, options)

        openvas_results = []
        if options.get("openvas"):
            openvas_results = self._launch_openvas_scans(summary)

        twin_result = None
        if options.get("create_twin"):
            twin_result = self._create_digital_twin_scan(sim_system, expected_nodes)

        report = {
            "sim_system": str(sim_path),
            "summary": summary,
            "validation": validation,
            "discovery_scans": scan_results,
            "openvas_scans": openvas_results,
            "digital_twin": twin_result,
        }

        output_path = options.get("output")
        if output_path:
            out_path = Path(output_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(report, indent=2))
            self.stdout.write(self.style.SUCCESS(f"Wrote report to {out_path}"))

        self.stdout.write(json.dumps(report, indent=2))

    def _resolve_sim_system_path(self, options) -> Path:
        if options.get("sim_system"):
            path = Path(options["sim_system"]).expanduser()
            if not path.exists():
                raise SystemExit(f"sim_system.json not found: {path}")
            return path

        output_dir_value = getattr(settings, "PID_DRAWIO_OUTPUT_DIR", None)
        output_dir = Path(output_dir_value) if output_dir_value else Path(settings.BASE_DIR) / "out" / "pid_drawio"
        target_path_value = getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")
        target_path = Path(target_path_value) if target_path_value else None

        sim_path, _ = resolve_sim_system_path(options.get("source", "auto"), output_dir, target_path)
        if not sim_path:
            raise SystemExit("No sim_system.json found.")
        return sim_path

    def _load_discovered_ips(self, scan_run_id: Optional[int]) -> List[str]:
        nodes = Node.objects.all()
        if scan_run_id:
            nodes = nodes.filter(scan_run_id=scan_run_id)

        ips = list(nodes.values_list("ip_address", flat=True))
        interface_ips = list(NodeInterface.objects.filter(node__in=nodes).values_list("ip", flat=True))
        return [*ips, *interface_ips]

    def _launch_discovery_scans(self, summary: dict, options) -> List[dict]:
        method = options.get("scan")
        scan_sync = options.get("scan_sync")
        vlan_cidrs = []
        for cidr_list in summary.get("vlan_cidrs", {}).values():
            vlan_cidrs.extend(cidr_list)
        vlan_cidrs = sorted(set(vlan_cidrs))

        if not vlan_cidrs:
            self.stdout.write(self.style.WARNING("No vlan_cidr entries found in PID; skipping discovery scans."))
            return []

        results = []
        for cidr in vlan_cidrs:
            if method == "nmap":
                if scan_sync:
                    result = nmap_discovery_task(cidr)
                else:
                    result = nmap_discovery_task.delay(cidr)
            else:
                if scan_sync:
                    result = scan_network_task(cidr)
                else:
                    result = scan_network_task.delay(cidr)
            results.append({"cidr": cidr, "method": method, "result": str(result)})

        return results

    def _launch_openvas_scans(self, summary: dict) -> List[dict]:
        vlan_cidrs = []
        for cidr_list in summary.get("vlan_cidrs", {}).values():
            vlan_cidrs.extend(cidr_list)
        vlan_cidrs = sorted(set(vlan_cidrs))

        if not vlan_cidrs:
            self.stdout.write(self.style.WARNING("No vlan_cidr entries found in PID; skipping OpenVAS scans."))
            return []

        results = []
        for cidr in vlan_cidrs:
            result = launch_openvas_scan_task.delay(cidr)
            results.append({"cidr": cidr, "result": str(result)})
        return results

    def _create_digital_twin_scan(self, sim_system: dict, expected_nodes) -> dict:
        variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
        connections = sim_system.get("connections", []) if isinstance(sim_system, dict) else []

        ip_by_id = {node.node_id: node.ip for node in expected_nodes if node.ip}
        node_entries = []
        node_by_id = {}

        with transaction.atomic():
            scan = ScanRun.objects.create(
                cidr="pid",
                status="COMPLETE",
                scan_type="pid",
                result_summary="Digital twin generated from PID sim_system.json",
            )

            for var_id, info in variables.items():
                info = info if isinstance(info, dict) else {}
                if var_id not in ip_by_id:
                    continue
                ip_addr = ip_by_id[var_id]
                name = str(info.get("name") or var_id)
                description_parts = []
                if info.get("purdue_level"):
                    description_parts.append(f"Purdue: {info.get('purdue_level')}")
                if info.get("vlan"):
                    description_parts.append(f"VLAN: {info.get('vlan')}")
                if info.get("redundancy_group"):
                    description_parts.append(f"Redundancy: {info.get('redundancy_group')}")
                node = Node.objects.create(
                    scan_run=scan,
                    ip_address=ip_addr,
                    name=name,
                    status="online",
                    description=" | ".join(description_parts),
                )
                node_by_id[str(var_id)] = node
                node_entries.append({"id": node.id, "ip": ip_addr, "name": name})

            link_count = 0
            for conn in connections:
                if not isinstance(conn, dict):
                    continue
                source = str(conn.get("source"))
                target = str(conn.get("target"))
                if source in node_by_id and target in node_by_id:
                    Link.objects.create(scan_run=scan, source=node_by_id[source], destination=node_by_id[target], weight=1.0)
                    link_count += 1

        return {
            "scan_id": scan.id,
            "nodes": len(node_entries),
            "links": link_count,
        }
