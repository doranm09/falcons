#!/usr/bin/env python3
"""
Convert draw.io P&ID diagrams to sim_system.json and back.

Examples:
  python utils/scripts/knowledge_extraction_drawio.py \
      --input docs/examples/pid_drawio_example.xml \
      --output out/sim_system.json

  python utils/scripts/knowledge_extraction_drawio.py \
      --to-drawio \
      --input docs/examples/sim_system_example.json \
      --output out/pid_drawio_example.xml
"""

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
    parse_drawio_sim_system,
    save_sim_system,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Draw.io <-> sim_system.json converter")
    parser.add_argument("--input", required=True, help="Input draw.io XML or sim_system.json")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--to-drawio", action="store_true", help="Convert sim_system.json -> draw.io XML")
    parser.add_argument("--diagram-name", default="P&ID", help="Diagram name for draw.io output")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if args.to_drawio:
        sim_system = load_sim_system(input_path)
        xml = generate_drawio_from_sim_system(sim_system, diagram_name=args.diagram_name)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(xml, encoding="utf-8")
    else:
        sim_system = parse_drawio_sim_system(input_path)
        save_sim_system(output_path, sim_system)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
