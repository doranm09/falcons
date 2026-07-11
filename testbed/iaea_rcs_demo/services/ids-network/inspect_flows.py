#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ids_network_common import extract_numeric_keys, load_flows, matrix_from_flows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect IDS flow data from pcap files (raw records + numeric feature view)."
    )
    parser.add_argument("pcaps", nargs="+", help="paths to pcap files")
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="number of flow rows to preview for raw and numeric views (default: 5)",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation for raw flow preview (default: 2)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    pcap_paths = [Path(p) for p in args.pcaps]
    all_flows = load_flows(pcap_paths)
    all_keys = sorted({key for flow in all_flows for key in flow.keys()})
    numeric_keys = extract_numeric_keys(all_flows)
    matrix = matrix_from_flows(all_flows, numeric_keys)

    print(f"total flows: {len(all_flows)}")
    print(f"all keys: {len(all_keys)}")
    print(f"numeric keys: {len(numeric_keys)}")
    print(f"matrix shape: {matrix.shape}")

    print("\n=== all keys ===")
    print(json.dumps(all_keys, indent=args.indent))

    print("\n=== numeric keys ===")
    print(json.dumps(numeric_keys, indent=args.indent))

    preview_count = min(args.limit, len(all_flows))
    print(f"\n=== raw flow preview (first {preview_count}) ===")
    for idx in range(preview_count):
        print(f"flow[{idx}]:")
        print(json.dumps(all_flows[idx], indent=args.indent, default=str, sort_keys=True))

    print(f"\n=== numeric-only preview (first {preview_count}) ===")
    for idx in range(preview_count):
        numeric_row = {key: all_flows[idx].get(key) for key in numeric_keys}
        print(f"numeric_flow[{idx}]:")
        print(json.dumps(numeric_row, indent=args.indent, default=str, sort_keys=True))

    matrix_preview = min(args.limit, int(matrix.shape[0]))
    print(f"\n=== matrix preview (first {matrix_preview} rows) ===")
    for idx in range(matrix_preview):
        print(f"row[{idx}]: {matrix[idx].tolist()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
