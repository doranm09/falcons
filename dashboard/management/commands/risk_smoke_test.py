from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Run integration smoke tests against the risk assessment API."

    def add_arguments(self, parser):
        parser.add_argument(
            "--base-url",
            default=None,
            help="Risk assessment API base URL (default: settings.RISK_ASSESSMENT_API_URL)",
        )
        parser.add_argument(
            "--sim-system",
            default=None,
            help="Optional path to sim_system.json to POST to /sim-system before tests.",
        )
        parser.add_argument(
            "--nodes-limit",
            type=int,
            default=8,
            help="Number of nodes to query for /evidence (default: 8).",
        )
        parser.add_argument(
            "--skip-probability",
            action="store_true",
            help="Skip the /probability smoke test.",
        )
        parser.add_argument(
            "--force-probability",
            action="store_true",
            help="Run /probability even if nodes_count is large.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=20,
            help="Request timeout in seconds (default: 20).",
        )

    def handle(self, *args, **options):
        base_url = options["base_url"] or getattr(settings, "RISK_ASSESSMENT_API_URL", "http://127.0.0.1:7890")
        base_url = base_url.rstrip("/")
        timeout = options["timeout"]

        def _url(path: str) -> str:
            return f"{base_url}/{path.lstrip('/')}"

        self.stdout.write(self.style.NOTICE(f"Risk API: {base_url}"))

        sim_system_path = options.get("sim_system")
        if sim_system_path:
            sim_path = Path(sim_system_path)
            if not sim_path.exists():
                raise SystemExit(f"sim_system.json not found: {sim_path}")
            try:
                payload = json.loads(sim_path.read_text())
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Invalid JSON in {sim_path}: {exc}")
            self.stdout.write("Posting sim_system.json to /sim-system …")
            resp = requests.post(_url("/sim-system"), json=payload, timeout=timeout)
            if not resp.ok:
                raise SystemExit(f"/sim-system failed: {resp.status_code} {resp.text}")
            self.stdout.write(self.style.SUCCESS(f"/sim-system ok: {resp.json()}"))

        self.stdout.write("Checking /status …")
        status_resp = requests.get(_url("/status"), timeout=timeout)
        if not status_resp.ok:
            raise SystemExit(f"/status failed: {status_resp.status_code} {status_resp.text}")
        status = status_resp.json()
        self.stdout.write(self.style.SUCCESS(f"/status ok: dbn_loaded={status.get('dbn_loaded')}"))

        self.stdout.write("Fetching /nodes …")
        nodes_resp = requests.get(_url("/nodes"), timeout=timeout)
        if not nodes_resp.ok:
            raise SystemExit(f"/nodes failed: {nodes_resp.status_code} {nodes_resp.text}")
        nodes_payload = nodes_resp.json()

        variables = nodes_payload.get("variables", {}) if isinstance(nodes_payload, dict) else {}
        risk_nodes = list(variables.keys()) if isinstance(variables, dict) else []
        if not risk_nodes:
            nodes_list = nodes_payload.get("nodes") if isinstance(nodes_payload, dict) else []
            if isinstance(nodes_list, list):
                for node in nodes_list:
                    if isinstance(node, str):
                        risk_nodes.append(node)
                    elif isinstance(node, dict):
                        name = node.get("name") or node.get("node") or node.get("id")
                        if name:
                            risk_nodes.append(str(name))

        if not risk_nodes:
            raise SystemExit("/nodes returned no node identifiers.")

        nodes_limit = max(1, int(options["nodes_limit"]))
        sample_nodes = risk_nodes[:nodes_limit]

        self.stdout.write(f"Running /evidence on {len(sample_nodes)} nodes …")
        evidence_payload = {
            "T": 1,
            "evidence": {},
            "nodes": sample_nodes,
        }
        evidence_resp = requests.post(_url("/evidence"), json=evidence_payload, timeout=timeout)
        if not evidence_resp.ok:
            raise SystemExit(f"/evidence failed: {evidence_resp.status_code} {evidence_resp.text}")
        self.stdout.write(self.style.SUCCESS("/evidence ok"))

        skip_probability = options["skip_probability"]
        force_probability = options["force_probability"]
        nodes_count = len(risk_nodes)
        if not skip_probability:
            if nodes_count > 2000 and not force_probability:
                self.stdout.write(self.style.WARNING(
                    f"Skipping /probability because nodes_count={nodes_count}. Use --force-probability to run."
                ))
            else:
                self.stdout.write("Running /probability with empty scanned_nodes …")
                prob_payload = {"scanned_nodes": []}
                prob_resp = requests.post(_url("/probability"), json=prob_payload, params={"T": 1}, timeout=timeout)
                if not prob_resp.ok:
                    raise SystemExit(f"/probability failed: {prob_resp.status_code} {prob_resp.text}")
                self.stdout.write(self.style.SUCCESS("/probability ok"))

        self.stdout.write(self.style.SUCCESS("Risk smoke test completed."))
