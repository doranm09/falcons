#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path

import numpy as np


ALLOWED_FEATURE_PREFIXES = (
    "bidirectional_",
    "src2dst_",
    "dst2src_",
)

ARGUS_BASE_FIELDS = (
    "startime",
    "saddr",
    "sport",
    "proto",
    "daddr",
    "dport",
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
)

# Broad Argus flow features supported by ra -s (version dependent).
ARGUS_EXTENDED_FIELDS = (
    "srcid",
    "stime",
    "ltime",
    "sstime",
    "dstime",
    "sltime",
    "dltime",
    "trans",
    "seq",
    "flgs",
    "dur",
    "avgdur",
    "stddev",
    "mindur",
    "maxdur",
    "saddr",
    "daddr",
    "proto",
    "sport",
    "dport",
    "stos",
    "dtos",
    "sdsb",
    "ddsb",
    "sco",
    "dco",
    "sttl",
    "dttl",
    "sipid",
    "dipid",
    "smpls",
    "dmpls",
    "svlan",
    "dvlan",
    "svid",
    "dvid",
    "svpri",
    "dvpri",
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
    "smac",
    "dmac",
    "dir",
    "sintpkt",
    "dintpkt",
    "sjit",
    "djit",
    "state",
    "suser",
    "duser",
    "swin",
    "dwin",
    "srng",
    "erng",
    "stcpb",
    "dtcpb",
    "tcprtt",
    "inode",
    "offset",
    "smaxsz",
    "dmaxsz",
    "sminsz",
    "dminsz",
)

HEADER_ALIAS_MAP = {
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
    "starttime": "startime",
    "lasttime": "ltime",
    "srcaddr": "saddr",
    "dstaddr": "daddr",
    "srcpkts": "spkts",
    "dstpkts": "dpkts",
    "totpkts": "totpkts",
    "srcbytes": "sbytes",
    "dstbytes": "dbytes",
    "totbytes": "totbytes",
    "sappbytes": "sappbytes",
    "dappbytes": "dappbytes",
    "srcload": "sload",
    "dstload": "dload",
    "srcloss": "sloss",
    "dstloss": "dloss",
    "psrcloss": "sploss",
    "pdstloss": "dploss",
    "srcrate": "srate",
    "dstrate": "drate",
    "srcjitter": "sjit",
    "dstjitter": "djit",
    "smaxpktsz": "smaxsz",
    "dmaxpktsz": "dmaxsz",
    "sminpktsz": "sminsz",
    "dminpktsz": "dminsz",
    "srcid": "srcid",
}

NON_FEATURE_KEYS = {
    "startime",
    "stime",
    "ltime",
    "sstime",
    "dstime",
    "sltime",
    "dltime",
    "saddr",
    "daddr",
    "proto",
    "sport",
    "dport",
    "smac",
    "dmac",
    "state",
    "flgs",
    "dir",
    "srcid",
    "suser",
    "duser",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "src_mac",
    "dst_mac",
    "protocol",
}


def _resolve_backend(backend: str | None, *, env_var: str, default: str) -> str:
    resolved = (backend or os.environ.get(env_var, default)).strip().lower()
    if resolved not in {"nfstream", "argus"}:
        raise ValueError(f"unsupported IDS backend {resolved!r}")
    return resolved


def _make_temp_argus_path(prefix: str) -> str:
    with tempfile.NamedTemporaryFile(prefix=prefix, suffix=".argus", delete=False) as handle:
        return handle.name


def _normalize_header_key(header: str) -> str:
    compact = "".join(ch for ch in header if ch.isalnum()).lower()
    return HEADER_ALIAS_MAP.get(compact, compact)


def _normalize_key(header: str) -> str:
    return _normalize_header_key(header)


def _safe_ratio(num: float, den: float) -> float:
    if den <= 0.0:
        return 0.0
    return num / den


def _flow_metric(flow: dict[str, object], key: str) -> float:
    value = flow.get(key)
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _looks_like_argus_flow(flow: dict[str, object]) -> bool:
    return any(key in flow for key in ("saddr", "daddr", "spkts", "dpkts", "sbytes", "dbytes"))


def _derive_flow_features(flow: dict[str, object]) -> None:
    sbytes = _flow_metric(flow, "sbytes")
    dbytes = _flow_metric(flow, "dbytes")
    spkts = _flow_metric(flow, "spkts")
    dpkts = _flow_metric(flow, "dpkts")
    sappbytes = _flow_metric(flow, "sappbytes")
    dappbytes = _flow_metric(flow, "dappbytes")
    dur = _flow_metric(flow, "dur")
    sttl = _flow_metric(flow, "sttl")
    dttl = _flow_metric(flow, "dttl")

    total_bytes = sbytes + dbytes
    total_pkts = spkts + dpkts
    total_appbytes = sappbytes + dappbytes

    flow["src2dst_bytes"] = sbytes
    flow["dst2src_bytes"] = dbytes
    flow["src2dst_packets"] = spkts
    flow["dst2src_packets"] = dpkts
    flow["src2dst_appbytes"] = sappbytes
    flow["dst2src_appbytes"] = dappbytes
    flow["bidirectional_bytes"] = total_bytes
    flow["bidirectional_packets"] = total_pkts
    flow["bidirectional_appbytes"] = total_appbytes
    flow["src2dst_avg_pkt_size"] = _safe_ratio(sbytes, spkts)
    flow["dst2src_avg_pkt_size"] = _safe_ratio(dbytes, dpkts)
    flow["bytes_ratio_src_dst"] = _safe_ratio(sbytes, dbytes)
    flow["packets_ratio_src_dst"] = _safe_ratio(spkts, dpkts)
    flow["appbytes_ratio_src_dst"] = _safe_ratio(sappbytes, dappbytes)
    flow["src_avg_pkt_size"] = _safe_ratio(sbytes, spkts)
    flow["dst_avg_pkt_size"] = _safe_ratio(dbytes, dpkts)
    flow["bidirectional_avg_pkt_size"] = _safe_ratio(total_bytes, total_pkts)
    flow["src2dst_bytes_per_second"] = _safe_ratio(sbytes, dur)
    flow["dst2src_bytes_per_second"] = _safe_ratio(dbytes, dur)
    flow["bytes_per_second"] = _safe_ratio(total_bytes, dur)
    flow["src2dst_packets_per_second"] = _safe_ratio(spkts, dur)
    flow["dst2src_packets_per_second"] = _safe_ratio(dpkts, dur)
    flow["packets_per_second"] = _safe_ratio(total_pkts, dur)
    flow["src2dst_appbytes_per_second"] = _safe_ratio(sappbytes, dur)
    flow["dst2src_appbytes_per_second"] = _safe_ratio(dappbytes, dur)
    flow["appbytes_per_second"] = _safe_ratio(total_appbytes, dur)
    flow["bidirectional_duration_ms"] = dur * 1000.0
    if sttl:
        flow["src2dst_ttl"] = sttl
    if dttl:
        flow["dst2src_ttl"] = dttl


def _normalize_argus_flow(flow: dict[str, object]) -> dict[str, object]:
    normalized = dict(flow)
    if "startime" in normalized and "bidirectional_first_seen_ms" not in normalized:
        normalized["bidirectional_first_seen_ms"] = normalized["startime"]
    if "saddr" in normalized and "src_ip" not in normalized:
        normalized["src_ip"] = normalized["saddr"]
    if "daddr" in normalized and "dst_ip" not in normalized:
        normalized["dst_ip"] = normalized["daddr"]
    if "sport" in normalized and "src_port" not in normalized:
        normalized["src_port"] = normalized["sport"]
    if "dport" in normalized and "dst_port" not in normalized:
        normalized["dst_port"] = normalized["dport"]
    if "smac" in normalized and "src_mac" not in normalized:
        normalized["src_mac"] = normalized["smac"]
    if "dmac" in normalized and "dst_mac" not in normalized:
        normalized["dst_mac"] = normalized["dmac"]
    if "proto" in normalized and "protocol" not in normalized:
        normalized["protocol"] = normalized["proto"]
    _derive_flow_features(normalized)
    return normalized


def _run_argus(source: str, output_file: str | None = None, is_live: bool = False) -> str:
    """Run argus to process a PCAP file or live interface."""
    if output_file is None:
        output_file = _make_temp_argus_path("argus_")

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

        flow_dict: dict[str, object] = {}
        for header, value in zip(headers, values):
            try:
                if "." in value or "e" in value.lower():
                    parsed_value: object = float(value)
                else:
                    parsed_value = int(value)
            except (ValueError, AttributeError):
                parsed_value = value

            flow_dict[header] = parsed_value
            flow_dict[_normalize_header_key(header)] = parsed_value
        flows.append(_normalize_argus_flow(flow_dict))

    return flows


def _get_flows_from_argus(argus_file: str) -> list[dict]:
    """Convert argus records to flow dictionaries using ra client."""
    fields = ",".join(ARGUS_EXTENDED_FIELDS)
    # Exclude Argus management records (MAR) from flow output.
    cmd = ["ra", "-r", argus_file, "-M", "noman", "-n", "-c", ",", "-s", fields]

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
        flows = _parse_ra_csv(result.stdout)
    except subprocess.CalledProcessError as e:
        # Fall back to a conservative field set if this Argus version lacks some fields.
        base_fields = ",".join(ARGUS_BASE_FIELDS)
        fallback_cmd = ["ra", "-r", argus_file, "-M", "noman", "-n", "-c", ",", "-s", base_fields]
        try:
            result = subprocess.run(fallback_cmd, check=True, capture_output=True, text=True, timeout=60)
            flows = _parse_ra_csv(result.stdout)
        except subprocess.CalledProcessError as fallback_error:
            raise RuntimeError(f"ra failed: {fallback_error.stderr}") from e
    except subprocess.TimeoutExpired:
        raise RuntimeError("ra processing timed out")

    return flows


def flow_to_dict(flow: object) -> dict:
    if isinstance(flow, dict):
        values = dict(flow)
    elif hasattr(flow, "to_dict"):
        values = flow.to_dict()
    elif hasattr(flow, "_asdict"):
        values = dict(flow._asdict())
    else:
        try:
            values = dict(vars(flow))
        except TypeError:
            values = {}
            for key in dir(flow):
                if key.startswith("_"):
                    continue
                try:
                    value = getattr(flow, key)
                except Exception:
                    # Some NFStream attributes are listed in dir() but are not readable.
                    continue
                if callable(value):
                    continue
                values[key] = value

    if _looks_like_argus_flow(values):
        return _normalize_argus_flow(values)
    return values


def _flows_from_pcap_nfstream(pcap_path: Path) -> list[dict]:
    from nfstream import NFStreamer

    streamer = NFStreamer(source=str(pcap_path), statistical_analysis=True)
    frame = streamer.to_pandas(columns_to_anonymize=())
    return frame.to_dict(orient="records")


def _flows_from_pcap_argus(pcap_path: Path) -> list[dict]:
    argus_file = _run_argus(str(pcap_path), is_live=False)

    try:
        return _get_flows_from_argus(argus_file)
    finally:
        try:
            Path(argus_file).unlink(missing_ok=True)
        except Exception:
            pass


def flows_from_pcap(pcap_path: Path, backend: str | None = None) -> list[dict]:
    selected_backend = _resolve_backend(backend, env_var="IDS_PCAP_BACKEND", default="nfstream")
    if selected_backend == "argus":
        return _flows_from_pcap_argus(pcap_path)
    return _flows_from_pcap_nfstream(pcap_path)


def _iter_flows_from_interface_nfstream(
    interface: str,
    idle_timeout: int = 1,
    active_timeout: int = 1,
):
    from nfstream import NFStreamer

    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
    )
    for flow in streamer:
        yield flow_to_dict(flow)


def _iter_flows_from_interface_argus(interface: str):
    argus_file = _make_temp_argus_path("argus_live_")
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
                # ra can fail briefly while argus is still appending to the flow file.
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


def iter_flows_from_interface(
    interface: str,
    idle_timeout: int = 1,
    active_timeout: int = 1,
    backend: str | None = None,
):
    selected_backend = _resolve_backend(backend, env_var="IDS_INTERFACE_BACKEND", default="argus")
    if selected_backend == "nfstream":
        yield from _iter_flows_from_interface_nfstream(
            interface,
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
        )
        return
    yield from _iter_flows_from_interface_argus(interface)


def load_flows(pcap_paths: list[Path], backend: str | None = None) -> list[dict]:
    all_flows: list[dict] = []
    for pcap in pcap_paths:
        flows = flows_from_pcap(pcap, backend=backend)
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
    if not flows:
        return []

    candidate_keys: set[str] = set()
    for flow in flows:
        candidate_keys.update(flow.keys())

    prefixed_keys = [
        key
        for key in sorted(candidate_keys)
        if any(key.startswith(prefix) for prefix in ALLOWED_FEATURE_PREFIXES)
    ]
    if prefixed_keys:
        keys_to_check = prefixed_keys
    else:
        keys_to_check = [key for key in sorted(candidate_keys) if key not in NON_FEATURE_KEYS]

    numeric_keys: list[str] = []
    for key in keys_to_check:
        numeric = True
        saw_value = False
        for flow in flows:
            value = flow.get(key)
            if value is None:
                continue
            saw_value = True
            try:
                _coerce_float(value)
            except (TypeError, ValueError):
                numeric = False
                break
        if numeric and saw_value:
            numeric_keys.append(key)

    return numeric_keys


def matrix_from_flows(flows: list[dict], numeric_keys: list[str]) -> np.ndarray:
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
