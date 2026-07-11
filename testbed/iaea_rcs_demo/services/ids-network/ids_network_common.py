#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

import numpy as np




ARGUS_FIELDS = (
    "srcid",     # Argus source identifier.
    "stime",     # record start time
    "ltime",     # record last time.
    "sstime",    # source start time.
    "dstime",    # destination start time.
    "sltime",    # source last time.
    "dltime",    # destination last time.
    "seq",       # argus sequence number.
    "saddr",     # source IP addr.
    "daddr",     # destination IP addr.
    "proto",     # transaction protocol.
    "sport",     # source port number.
    "dport",     # destination port number.
    "stos",      # source TOS byte value.
    "dtos",      # destination TOS byte value.
    "sdsb",      # source diff serve byte value.
    "ddsb",      # destination diff serve byte value.
    "sco",       # source IP address country code.
    "dco",       # destination IP address country code.
    "sipid",     # source IP identifier.
    "dipid",     # destination IP identifier.
    "smpls",     # source MPLS identifier.
    "dmpls",     # destination MPLS identifier.
    "svlan",     # source VLAN identifier.
    "dvlan",     # destination VLAN identifier.
    "svid",      # source VLAN identifier.
    "dvid",      # destination VLAN identifier.
    "svpri",     # source VLAN priority.
    "dvpri",     # destination VLAN priority.
    "smac",      # source MAC addr.
    "dmac",      # destination MAC addr.
    "dir",       # direction of transaction
    "state",     # transaction state
    "flgs",      # flow state flags seen in transaction.
    "suser",     # source user data buffer.
    "duser",     # destination user data buffer.
    "swin",      # source TCP window advertisement.
    "dwin",      # destination TCP window advertisement.
    "stcpb",     # source TCP base sequence number
    "dtcpb",     # destination TCP base sequence number
    "srng",      # start time for the filter timerange.
    "erng",      # end time for the filter timerange.
    "inode",     # ICMP intermediate node.
    "offset",    # record byte offset in file or stream.

    "trans",       # aggregation record count.
    "dur",         # record total duration.
    "avgdur",      # average duration of aggregated records.
    "stddev",      # standard deviation of aggregated duration times.
    "mindur",      # minimum duration of aggregated records.
    "maxdur",      # maximum duration of aggregated records.
    "sttl",        # src -> dst TTL value.
    "dttl",        # dst -> src TTL value.
    "spkts",       # src -> dst packet count.
    "dpkts",       # dst -> src packet count.
    "sbytes",      # src -> dst transaction bytes.
    "dbytes",      # dst -> src transaction bytes.
    "sappbytes",   # src -> dst application bytes.
    "dappbytes",   # dst -> src application bytes.
    "sload",       # source bits per second.
    "dload",       # destination bits per second.
    "sloss",       # source pkts retransmitted or dropped.
    "dloss",       # destination pkts retransmitted or dropped.
    "sploss",      # percent source pkts retransmitted or dropped.
    "dploss",      # percent destination pkts retransmitted or dropped.
    "srate",       # source pkts per second.
    "drate",       # destination pkts per second.
    "sintpkt",     # source interpacket arrival time (mSec)
    "dintpkt",     # destination interpacket arrival time (mSec)
    "sjit",        # source jitter (mSec).
    "djit",        # destination jitter (mSec).
    "tcprtt",      # TCP connection setup round-trip time.
    "smaxsz",      # maximum packet size for traffic transmitted by the src.
    "dmaxsz",      # maximum packet size for traffic transmitted by the dst.
    "sminsz",      # minimum packet size for traffic transmitted by the src.
    "dminsz",      # minimum packet size for traffic transmitted by the dst.
)

# Canonical ML feature schema. Keep this stable so model training/inference
# uses a fixed column order and missing fields are zero-filled.
ARGUS_ML_FEATURE_FIELDS = (
    "trans",
    "dur",
    "avgdur",
    "stddev",
    "mindur",
    "maxdur",
    "sttl",
    "dttl",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sappbytes",
    "dappbytes",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sploss",
    "dploss",
    "srate",
    "drate",
    "sintpkt",
    "dintpkt",
    "sjit",
    "djit",
    "tcprtt",
    "smaxsz",
    "dmaxsz",
    "sminsz",
    "dminsz",
)

ARGUS_HEADER_NORMALIZATION = {
    "proto": "proto",
    "protocol": "proto",
    "sport": "sport",
    "dport": "dport",
    "srcport": "sport",
    "dstport": "dport",
    "saddr": "saddr",
    "daddr": "daddr",
    "smac": "smac",
    "dmac": "dmac",
    "trans": "trans",
    "dur": "dur",
    "avgdur": "avgdur",
    "stddev": "stddev",
    "mindur": "mindur",
    "maxdur": "maxdur",
    "srcpkts": "spkts",
    "dstpkts": "dpkts",
    "spkts": "spkts",
    "dpkts": "dpkts",
    "srcbytes": "sbytes",
    "dstbytes": "dbytes",
    "sbytes": "sbytes",
    "dbytes": "dbytes",
    "sappbytes": "sappbytes",
    "dappbytes": "dappbytes",
    "srcload": "sload",
    "dstload": "dload",
    "sload": "sload",
    "dload": "dload",
    "srcloss": "sloss",
    "dstloss": "dloss",
    "sloss": "sloss",
    "dloss": "dloss",
    "psrcloss": "sploss",
    "pdstloss": "dploss",
    "sploss": "sploss",
    "dploss": "dploss",
    "srcrate": "srate",
    "dstrate": "drate",
    "srate": "srate",
    "drate": "drate",
    "sintpkt": "sintpkt",
    "dintpkt": "dintpkt",
    "srcjitter": "sjit",
    "dstjitter": "djit",
    "sjit": "sjit",
    "djit": "djit",
    "tcprtt": "tcprtt",
    "smaxpktsz": "smaxsz",
    "dmaxpktsz": "dmaxsz",
    "smaxsz": "smaxsz",
    "dmaxsz": "dmaxsz",
    "sminpktsz": "sminsz",
    "dminpktsz": "dminsz",
    "sminsz": "sminsz",
    "dminsz": "dminsz",
    "sttl": "sttl",
    "dttl": "dttl",
    "sttl": "sttl",
    "dttl": "dttl",
    "srcaddr": "saddr",
    "dstaddr": "daddr",
}


def _normalize_key(header: str) -> str:
    token = "".join(ch for ch in header if ch.isalnum()).lower()
    return ARGUS_HEADER_NORMALIZATION.get(token, token)


def _coerce_numeric_or_zero(value: object) -> float:
    """Return finite float value, defaulting to 0.0 for missing/non-numeric inputs."""
    if value is None or value == "":
        return 0.0
    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not np.isfinite(numeric_value):
        return 0.0
    return numeric_value


def _run_argus(source: str, output_file: str | None = None, is_live: bool = False) -> str:
    """Run argus to process a PCAP file or live interface."""
    if output_file is None:
        output_file = tempfile.mktemp(prefix="argus_", suffix=".argus")

    # Ignore system argus.conf; Debian default uses hostuuid which fails in containers.
    cmd = ["argus", "-F", "/dev/null"]
    if is_live:
        cmd.extend(["-i", source])
    else:
        cmd.extend(["-r", source])
    cmd.extend(["-w", output_file])

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=300)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"argus failed: {e.stderr.decode()}") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("argus processing timed out") from e

    return output_file


def _parse_ra_csv(ra_output: str) -> list[dict]:
    """Parse ra CSV output into list of flow dictionaries."""
    flows = []
    lines = ra_output.strip().split("\n")

    if not lines or len(lines) < 2:
        return flows

    headers = [h.strip() for h in lines[0].split(",")]

    for line in lines[1:]:
        if not line.strip():
            continue
        values = [v.strip() for v in line.split(",")]

        if len(values) != len(headers):
            continue

        flow_dict = {}
        for header, value in zip(headers, values):
            try:
                if "." in value or "e" in value.lower():
                    parsed_value: object = float(value)
                else:
                    parsed_value = int(value)
            except (ValueError, AttributeError):
                parsed_value = value

            flow_dict[_normalize_key(header)] = parsed_value

        # Force a complete numeric ML schema in each row so debugging views
        # and downstream matrix conversion do not carry null/empty values.
        for key in ARGUS_ML_FEATURE_FIELDS:
            flow_dict[key] = _coerce_numeric_or_zero(flow_dict.get(key))

        flows.append(flow_dict)

    return flows


def _get_flows_from_argus(argus_file: str) -> list[dict]:
    """Convert argus records to flow dictionaries using ra client."""
    fields = ",".join(ARGUS_FIELDS)
    # Exclude Argus management records (MAR) from flow output.
    cmd = ["ra", "-r", argus_file, "-M", "noman", "-n", "-c", ",", "-s", fields]

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
        flows = _parse_ra_csv(result.stdout)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"ra failed: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("ra processing timed out") from e

    return flows


def flow_to_dict(flow: dict) -> dict:
    """Ensure flow is a dictionary."""
    if isinstance(flow, dict):
        return flow

    if hasattr(flow, "to_dict"):
        return flow.to_dict()

    if hasattr(flow, "_asdict"):
        return dict(flow._asdict())

    try:
        return dict(vars(flow))
    except TypeError:
        return {}


def flows_from_pcap(pcap_path: Path) -> list[dict]:
    """Extract flows from a PCAP file using argus and ra."""
    argus_file = _run_argus(str(pcap_path), is_live=False)

    try:
        return _get_flows_from_argus(argus_file)
    finally:
        try:
            Path(argus_file).unlink(missing_ok=True)
        except Exception:
            pass


def iter_flows_from_interface(interface: str):
    """Capture flows from a live interface using argus and ra."""
    argus_file = tempfile.mktemp(prefix="argus_live_", suffix=".argus")

    cmd = ["argus", "-F", "/dev/null", "-i", interface, "-w", argus_file]
    argus_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        last_flow_count = 0

        while True:
            try:
                flows = _get_flows_from_argus(argus_file)
                new_flows = flows[last_flow_count:]
                for flow in new_flows:
                    yield flow_to_dict(flow)

                last_flow_count = len(flows)
                time.sleep(0.5)
            except Exception:
                time.sleep(0.5)
                continue

    except KeyboardInterrupt:
        pass
    finally:
        argus_proc.terminate()
        try:
            argus_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            argus_proc.kill()

        try:
            Path(argus_file).unlink(missing_ok=True)
        except Exception:
            pass


def load_flows(pcap_paths: list[Path]) -> list[dict]:
    """Load flows from one or more PCAP files."""
    all_flows: list[dict] = []
    for pcap in pcap_paths:
        flows = flows_from_pcap(pcap)
        print(f"loaded {len(flows)} flows from {pcap}")
        all_flows.extend(flows)
    return all_flows


def _coerce_float(value: object) -> float:
    if value is None:
        raise TypeError("missing value")
    if isinstance(value, bool):
        numeric_value = float(value)
    else:
        numeric_value = float(value)
    if not np.isfinite(numeric_value):
        raise ValueError("non-finite value")
    return numeric_value


def extract_numeric_keys(flows: list[dict]) -> list[str]:
    """Return fixed canonical ML feature keys.

    Missing fields are handled as 0.0 in matrix_from_flows().
    """
    return list(ARGUS_ML_FEATURE_FIELDS)


def matrix_from_flows(flows: list[dict], numeric_keys: list[str]) -> np.ndarray:
    """Convert flows to numeric feature matrix."""
    if not flows or not numeric_keys:
        return np.empty((0, 0), dtype=np.float64)

    matrix: list[list[float]] = []
    for flow in flows:
        row: list[float] = []
        for key in numeric_keys:
            value = flow.get(key)
            try:
                row.append(_coerce_float(value))
            except (TypeError, ValueError):
                row.append(0.0)
        matrix.append(row)
    return np.nan_to_num(np.asarray(matrix, dtype=np.float64), nan=0.0, posinf=0.0, neginf=0.0)


def standardize_matrix(
    matrix: np.ndarray,
    mean: np.ndarray | None = None,
    std: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Standardize feature matrix to zero mean and unit variance."""
    eps = 1e-9

    if matrix.size == 0:
        empty = np.empty((0,), dtype=np.float64)
        return matrix.astype(np.float64, copy=False), empty, empty

    if mean is None:
        mean = np.mean(matrix, axis=0)
    else:
        mean = np.asarray(mean, dtype=np.float64)

    if std is None:
        std = np.std(matrix, axis=0)
    else:
        std = np.asarray(std, dtype=np.float64)

    standardized = (matrix - mean) / (std + eps)
    standardized = np.nan_to_num(standardized, nan=0.0, posinf=0.0, neginf=0.0)
    return standardized.astype(np.float64, copy=False), mean, std
