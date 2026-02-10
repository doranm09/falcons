from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand

from knowledge_extraction.drawio import (
    generate_drawio_from_sim_system,
    load_sim_system,
    parse_drawio_sim_system,
    save_sim_system,
)


class Command(BaseCommand):
    help = "Convert draw.io P&ID XML to sim_system.json and back."

    def add_arguments(self, parser):
        parser.add_argument("--input", required=True, help="Input draw.io XML or sim_system.json")
        parser.add_argument("--output", required=True, help="Output file path")
        parser.add_argument("--to-drawio", action="store_true", help="Convert sim_system.json -> draw.io XML")
        parser.add_argument("--diagram-name", default="P&ID", help="Diagram name for draw.io output")

    def handle(self, *args, **options):
        input_path = Path(options["input"])
        output_path = Path(options["output"])

        if options["to_drawio"]:
            sim_system = load_sim_system(input_path)
            xml = generate_drawio_from_sim_system(sim_system, diagram_name=options["diagram_name"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(xml, encoding="utf-8")
            self.stdout.write(self.style.SUCCESS(f"Wrote draw.io XML to {output_path}"))
            return

        sim_system = parse_drawio_sim_system(input_path)
        save_sim_system(output_path, sim_system)
        self.stdout.write(self.style.SUCCESS(f"Wrote sim_system JSON to {output_path}"))
