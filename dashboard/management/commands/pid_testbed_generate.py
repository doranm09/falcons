from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from dashboard.pid_system import load_sim_system_file, resolve_sim_system_path
from dashboard.pid_testbed import build_testbed_from_sim_system


class Command(BaseCommand):
    help = "Generate a docker-compose testbed and inventory.json from sim_system.json."

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
            "--output-dir",
            default=None,
            help="Output directory for the generated compose and inventory files.",
        )

    def handle(self, *args, **options):
        sim_path = self._resolve_sim_system_path(options)
        sim_system = load_sim_system_file(sim_path)

        output_dir = options.get("output_dir")
        if output_dir:
            output_dir = Path(output_dir)
        else:
            output_dir = Path(settings.BASE_DIR) / "out" / "pid_drawio"

        files = build_testbed_from_sim_system(sim_system, output_dir)
        self.stdout.write(self.style.SUCCESS(f"Compose: {files.compose_path}"))
        self.stdout.write(self.style.SUCCESS(f"Inventory: {files.inventory_path}"))

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
