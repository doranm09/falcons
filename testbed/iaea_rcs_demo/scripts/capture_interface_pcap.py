#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_SECONDS = 5
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "data" / "network"
DEFAULT_BUFFER_MB = 500


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture packets from a network interface to a pcap file using tshark."
    )
    parser.add_argument("interface", help="network interface to capture from, for example enx806d97424bc3")
    parser.add_argument(
        "seconds",
        nargs="?",
        type=float,
        default=DEFAULT_SECONDS,
        help=f"capture duration in seconds (default: {DEFAULT_SECONDS})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory to write the pcap file into (default: data/network)",
    )
    parser.add_argument(
        "--outfile",
        help="output pcap filename; default is <interface>.pcap in data/network",
    )
    parser.add_argument(
        "--buffer-mb",
        type=int,
        default=DEFAULT_BUFFER_MB,
        help=f"tshark capture buffer in MB (default: {DEFAULT_BUFFER_MB})",
    )
    return parser.parse_args()


def build_output_path(output_dir: Path, interface: str, outfile: str | None) -> Path:
    if outfile:
        return output_dir / outfile
    safe_interface = interface.replace("/", "_")
    return output_dir / f"{safe_interface}.pcap"


def run_capture(interface: str, seconds: float, output_path: Path, buffer_mb: int) -> None:
    command = [
        "tshark",
        "-i",
        interface,
        "-F",
        "pcap",
        "-w",
        str(output_path),
        "-B",
        str(buffer_mb),
    ]

    print("+", " ".join(command))
    process = subprocess.Popen(command)
    timed_out = False
    try:
        process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)

    if not timed_out and process.returncode not in (0, None):
        raise SystemExit(f"tshark exited with code {process.returncode}")


def capture_to_output(interface: str, seconds: float, output_path: Path, buffer_mb: int) -> None:
    with tempfile.NamedTemporaryFile(prefix="capture-", suffix=".pcap", dir="/tmp", delete=False) as tmp_file:
        temp_path = Path(tmp_file.name)

    try:
        run_capture(interface, seconds, temp_path, buffer_mb)
        shutil.move(str(temp_path), str(output_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def main() -> int:
    args = parse_args()
    if args.seconds <= 0:
        raise SystemExit("seconds must be greater than 0")

    if os.geteuid() != 0:
        print("warning: run with sudo or as root if tshark needs elevated permissions", file=sys.stderr)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = build_output_path(args.output_dir, args.interface, args.outfile)

    try:
        capture_to_output(args.interface, args.seconds, output_path, args.buffer_mb)
    except FileNotFoundError as exc:
        raise SystemExit("tshark is not installed or not available on PATH") from exc

    print(f"saved capture to: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
