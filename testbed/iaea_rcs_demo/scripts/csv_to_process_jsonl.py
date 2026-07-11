#!/usr/bin/env python3
"""
Generate JSONL dataset from PZRData_demo.csv for IDS process training.

This script:
1. Parses the PZRData_demo.csv file
2. Applies the same integer rounding and averaging as the PLC logic
3. Outputs a JSONL file suitable for IDS process anomaly detector training

Usage:
    python3 csv_to_process_jsonl.py --output /path/to/output.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Dict, List


def _parse_time_to_seconds(time_str: str) -> float:
    """Parse CSV time column to seconds (handles both seconds and MM:SS formats)."""
    time_str = time_str.strip()
    if not time_str:
        return 0.0
    parts = time_str.split(':')
    if len(parts) == 1:
        return float(parts[0])
    elif len(parts) == 2:
        return int(parts[0]) * 60 + float(parts[1])
    elif len(parts) == 3:
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    return 0.0


def _round_to_int(value: float) -> int:
    """Round to integer (simulating Modbus integer registers)."""
    return int(round(value))


def _calculate_average_pressure(pt455: int, pt456: int, pt457: int, pt458: int) -> int:
    """
    Calculate average pressure using the same logic as hybrid PLCs.
    
    PLC logic (rcs_main_channel_polling_hybrid-model.st, line 57):
        average_pressure := (channel_a_pv + channel_b_pv + channel_c_pv + channel_d_pv) / 4;
    
    All values are INT type, so this rounds automatically.
    """
    return (pt455 + pt456 + pt457 + pt458) // 4


def parse_csv(csv_path: Path) -> List[Dict]:
    """
    Parse PZRData_demo.csv and return list of dictionaries with processed values.
    
    Each row becomes:
    {
        "timestamp": float (seconds from start),
        "profile": "main" or "backup",
        "fields": {
            "average_pressure": int,
            "channel_a_pv": int,
            "channel_b_pv": int,
            "channel_c_pv": int,
            "channel_d_pv": int,
            "pt_455": int,
            "pt_456": int,
            "pt_457": int,
            "pt_458": int,
        }
    }
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    
    records = []
    
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse timestamp
            raw_time = row.get("Time", "").strip()
            if not raw_time:
                continue
            
            try:
                timestamp = _parse_time_to_seconds(raw_time)
            except ValueError:
                continue
            
            # Parse PT sensor values (all 4 PTs are identical in the CSV)
            try:
                pt455_val = _round_to_int(float(row.get("PT-455", "0")))
                pt456_val = _round_to_int(float(row.get("PT-456", "0")))
                pt457_val = _round_to_int(float(row.get("PT-457", "0")))
                pt458_val = _round_to_int(float(row.get("PT-458", "0")))
            except ValueError:
                continue
            
            # Calculate average pressure (matches PLC logic)
            avg_pressure = _calculate_average_pressure(
                pt455_val, pt456_val, pt457_val, pt458_val
            )
            
            # Create record for "main" profile (PLC main)
            record_main = {
                "timestamp": timestamp,
                "profile": "main",
                "fields": {
                    "average_pressure": avg_pressure,
                    "channel_a_pv": pt455_val,  # channel-a reads pt-455
                    "channel_b_pv": pt456_val,  # channel-b reads pt-456
                    "channel_c_pv": pt457_val,  # channel-c reads pt-457  
                    "channel_d_pv": pt458_val,  # channel-d reads pt-458
                    "pt_455": pt455_val,
                    "pt_456": pt456_val,
                    "pt_457": pt457_val,
                    "pt_458": pt458_val,
                }
            }
            records.append(record_main)
            
            # Create record for "backup" profile (PLC backup)
            # Backup PLC uses different PT mapping:
            # rcs_backup_channel_polling_hybrid-model.st:
            #   channel_a -> pt-456
            #   channel_b -> pt-457
            #   channel_c -> pt-455
            #   channel_d -> pt-456 (same as a)
            #   average_pressure = (pt456 + pt457 + pt455 + pt456) / 4
            avg_pressure_backup = _calculate_average_pressure(
                pt456_val, pt457_val, pt455_val, pt456_val
            )
            
            record_backup = {
                "timestamp": timestamp,
                "profile": "backup",
                "fields": {
                    "average_pressure": avg_pressure_backup,
                    "channel_a_pv": pt456_val,
                    "channel_b_pv": pt457_val,
                    "channel_c_pv": pt455_val,
                    "channel_d_pv": pt456_val,
                    "pt_455": pt455_val,
                    "pt_456": pt456_val,
                    "pt_457": pt457_val,
                    "pt_458": pt458_val,
                }
            }
            records.append(record_backup)
    
    return records


def write_jsonl(records: List[Dict], output_path: Path) -> None:
    """Write records to JSONL file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with output_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate JSONL dataset from PZRData_demo.csv for IDS process training"
    )
    parser.add_argument(
        "--csv-path",
        type=Path,
        default=Path("testbed/iaea_rcs_demo/simulated_data/PZRData_demo.csv"),
        help="Path to PZRData_demo.csv (default: testbed/iaea_rcs_demo/simulated_data/PZRData_demo.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("testbed/iaea_rcs_demo/models/ids-process/train_data.jsonl"),
        help="Output JSONL file path (default: testbed/iaea_rcs_demo/models/ids-process/train_data.jsonl)",
    )
    parser.add_argument(
        "--profile",
        choices=["main", "backup", "both"],
        default="main",
        help="Profile to include (default: main)",
    )
    parser.add_argument(
        "--start-time",
        type=float,
        default=0.0,
        help="Start time in seconds (default: 0.0)",
    )
    parser.add_argument(
        "--end-time",
        type=float,
        default=None,
        help="End time in seconds (default: all data)",
    )
    
    args = parser.parse_args()
    
    # Parse CSV
    print(f"Parsing CSV: {args.csv_path}")
    records = parse_csv(args.csv_path)
    
    # Filter by profile
    if args.profile != "both":
        records = [r for r in records if r["profile"] == args.profile]
        print(f"Filtered to profile: {args.profile} ({len(records)} records)")
    
    # Filter by time range
    before_time = len(records)
    records = [r for r in records if r["timestamp"] >= args.start_time]
    if args.end_time is not None:
        records = [r for r in records if r["timestamp"] <= args.end_time]
    print(f"Filtered to time range [{args.start_time}, {args.end_time or 'end'}] ({len(records)} records, excluded {before_time - len(records)})")
    
    # Summary of values
    if records:
        avg_pressures = [r["fields"]["average_pressure"] for r in records]
        print(f"\nAverage pressure statistics:")
        print(f"  Min: {min(avg_pressures)}")
        print(f"  Max: {max(avg_pressures)}")
        print(f"  Range: {max(avg_pressures) - min(avg_pressures)}")
        unique_values = sorted(set(avg_pressures))
        print(f"  Unique values: {unique_values}")
    
    # Write JSONL
    write_jsonl(records, args.output)
    print(f"\nWrote {len(records)} records to: {args.output}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
