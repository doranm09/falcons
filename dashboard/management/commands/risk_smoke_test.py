from __future__ import annotations

from pathlib import Path
from typing import Any

import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from dashboard.sim_system import build_risk_service_compatible_sim_system, load_sim_system_json


class Command(BaseCommand):
    help = "Run smoke tests against the current ICS risk assessment API."

    def add_arguments(self, parser):
        parser.add_argument(
            "--base-url",
            default=None,
            help="Risk assessment API base URL (default: settings.RISK_ASSESSMENT_API_URL)",
        )
        parser.add_argument(
            "--sim-system",
            default=None,
            help="Optional sim_system.json path to upload with /upload_model before tests.",
        )
        parser.add_argument(
            "--nodes-limit",
            type=int,
            default=8,
            help="Number of nodes to query with /get_probability (default: 8).",
        )
        parser.add_argument(
            "--skip-probability",
            action="store_true",
            help="Skip the /get_probability smoke test.",
        )
        parser.add_argument(
            "--skip-detection",
            action="store_true",
            help="Skip the /post_detection smoke test.",
        )
        parser.add_argument(
            "--force-probability",
            action="store_true",
            help="Run /get_probability even if nodes_count is large.",
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

        def _detail(response: requests.Response) -> str:
            try:
                payload = response.json()
            except Exception:
                payload = None
            if isinstance(payload, dict):
                for key in ("detail", "error", "message"):
                    value = payload.get(key)
                    if value:
                        return str(value)
            return response.text

        def _node_ids_from_payload(payload: Any) -> list[str]:
            nodes_obj = payload.get("nodes") if isinstance(payload, dict) else None
            if not isinstance(nodes_obj, dict):
                return []
            return sorted(str(node_id) for node_id in nodes_obj.keys() if str(node_id).strip())

        self.stdout.write(self.style.NOTICE(f"Risk API: {base_url}"))

        sim_system_path = options.get("sim_system")
        if sim_system_path:
            sim_path = Path(sim_system_path)
            if not sim_path.exists():
                raise SystemExit(f"sim_system.json not found: {sim_path}")
            try:
                payload = build_risk_service_compatible_sim_system(load_sim_system_json(sim_path))
            except Exception as exc:
                raise SystemExit(f"Failed to load sim_system.json from {sim_path}: {exc}")
            self.stdout.write("Uploading sim_system.json to /upload_model ...")
            resp = requests.post(_url("/upload_model"), json=payload, timeout=timeout)
            if not resp.ok:
                raise SystemExit(f"/upload_model failed: {resp.status_code} {_detail(resp)}")
            self.stdout.write(self.style.SUCCESS(f"/upload_model ok: {resp.json()}"))

        self.stdout.write("Checking /status ...")
        status_resp = requests.get(_url("/status"), timeout=timeout)
        if not status_resp.ok:
            raise SystemExit(f"/status failed: {status_resp.status_code} {_detail(status_resp)}")
        status = status_resp.json()
        self.stdout.write(self.style.SUCCESS(f"/status ok: dbn_loaded={status.get('dbn_loaded')}"))

        self.stdout.write("Fetching /nodes ...")
        nodes_resp = requests.get(_url("/nodes"), timeout=timeout)
        if not nodes_resp.ok:
            raise SystemExit(f"/nodes failed: {nodes_resp.status_code} {_detail(nodes_resp)}")
        risk_nodes = _node_ids_from_payload(nodes_resp.json())
        if not risk_nodes:
            raise SystemExit("/nodes returned no node identifiers.")

        nodes_limit = max(1, int(options["nodes_limit"]))
        sample_nodes = risk_nodes[:nodes_limit]

        if not options["skip_detection"]:
            self.stdout.write(f"Running /post_detection on {sample_nodes[0]} ...")
            detection_resp = requests.post(
                _url("/post_detection"),
                json={"T": 0, "nodes": {sample_nodes[0]: {"score": 0.5}}},
                timeout=timeout,
            )
            if not detection_resp.ok:
                raise SystemExit(f"/post_detection failed: {detection_resp.status_code} {_detail(detection_resp)}")
            self.stdout.write(self.style.SUCCESS("/post_detection ok"))

        skip_probability = options["skip_probability"]
        force_probability = options["force_probability"]
        nodes_count = len(risk_nodes)
        if not skip_probability:
            if nodes_count > 2000 and not force_probability:
                self.stdout.write(
                    self.style.WARNING(
                        f"Skipping /get_probability because nodes_count={nodes_count}. Use --force-probability to run."
                    )
                )
            else:
                self.stdout.write(f"Running /get_probability on {len(sample_nodes)} nodes ...")
                params = {"T": 1, "nodes": ",".join(sample_nodes)}
                prob_resp = requests.get(_url("/get_probability"), params=params, timeout=timeout)
                if not prob_resp.ok:
                    raise SystemExit(
                        f"/get_probability failed: {prob_resp.status_code} {_detail(prob_resp)}"
                    )
                self.stdout.write(self.style.SUCCESS("/get_probability ok"))

        self.stdout.write(self.style.SUCCESS("Risk smoke test completed."))
