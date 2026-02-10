#!/usr/bin/env python3
"""Sync sim_system.json from ics-risk-assessment and generate draw.io XML."""

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path when running as a script
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from knowledge_extraction.drawio import (
    generate_drawio_from_sim_system,
    load_sim_system,
    save_sim_system,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync sim_system.json from risk assessment repo")
    parser.add_argument(
        "--source",
        default=str(Path("..") / "ics-risk-assessment" / "db" / "sim_system.json"),
        help="Path to sim_system.json in ics-risk-assessment",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "out" / "pid_drawio"),
        help="Output directory for copied JSON and generated draw.io XML",
    )
    parser.add_argument(
        "--prefix",
        default="risk",
        help="Output filename prefix",
    )
    parser.add_argument(
        "--diagram-name",
        default="Risk System",
        help="Diagram name for draw.io output",
    )

    args = parser.parse_args()

    source_path = Path(args.source).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not source_path.exists():
        raise SystemExit(f"Source sim_system.json not found: {source_path}")

    sim_system = load_sim_system(source_path)

    json_path = output_dir / f"{args.prefix}_sim_system.json"
    save_sim_system(json_path, sim_system)

    xml_path = output_dir / f"{args.prefix}_pid_drawio.xml"
    xml = generate_drawio_from_sim_system(sim_system, diagram_name=args.diagram_name)
    xml_path.write_text(xml, encoding="utf-8")

    print(f"Copied sim_system.json -> {json_path}")
    print(f"Generated draw.io XML -> {xml_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
