from __future__ import annotations

import ipaddress
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Tuple

from django.utils.timezone import now

from knowledge_extraction.drawio import parse_drawio_sim_system, save_sim_system
from .pid_system import classify_domain, extract_ip

DEFAULT_PURDUE_SUBNETS = {
    "L0/1": "172.30.0.0/24",
    "L2": "172.30.1.0/24",
    "L3": "172.30.2.0/24",
    "L3.5": "172.30.3.0/24",
    "L4": "172.30.4.0/24",
    "L5": "172.30.5.0/24",
}

PURDUE_HINTS = [
    ("L5", ["vendor", "portal", "enterprise", "business", "it", "office"]),
    ("L4", ["enterprise-app", "erp", "mes", "corp"]),
    ("L3.5", ["dmz", "remote", "broker", "update", "jump", "gateway", "proxy"]),
    ("L3", ["hist", "historian", "server", "scada", "engineering", "ops"]),
    ("L2", ["plc", "rtu", "controller", "ied", "dcs", "hmi"]),
    ("L0/1", ["sensor", "actuator", "field", "valve", "pump", "motor", "transmitter"]),
]

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str, default_ext: str = ".xml") -> str:
    raw = Path(name).name
    stem = Path(raw).stem or "diagram"
    stem = SAFE_NAME_RE.sub("_", stem)
    stem = re.sub(r"_+", "_", stem).strip("._-") or "diagram"
    ext = Path(raw).suffix or default_ext
    if ext.lower() not in (".xml", ".drawio"):
        ext = default_ext
    return f"{stem}{ext}"


def build_timestamp_prefix() -> str:
    return now().strftime("%Y%m%d_%H%M%S")


def store_drawio_upload(upload, output_dir: Path, prefix: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{prefix}_{safe_filename(getattr(upload, 'name', 'diagram.xml'))}"
    xml_path = output_dir / filename
    with xml_path.open("wb") as handle:
        for chunk in upload.chunks():
            handle.write(chunk)
    return xml_path


def convert_drawio_to_sim_system(xml_path: Path, output_dir: Path, prefix: str) -> Tuple[Dict[str, Any], Path]:
    sim_system = parse_drawio_sim_system(xml_path)
    _enrich_sim_system_network(sim_system)
    output_dir.mkdir(parents=True, exist_ok=True)
    sim_path = output_dir / f"{prefix}_sim_system.json"
    save_sim_system(sim_path, sim_system)
    return sim_system, sim_path


def _infer_purdue(label: str, role: str) -> str | None:
    haystack = f"{label} {role}".lower()
    for tier, hints in PURDUE_HINTS:
        if any(hint in haystack for hint in hints):
            return tier
    return None


def _next_ip(subnet: str, counters: Dict[str, int]) -> str:
    net = ipaddress.ip_network(subnet, strict=False)
    offset = counters.get(subnet, 10)
    counters[subnet] = offset + 1
    hosts = list(net.hosts())
    index = max(0, min(len(hosts) - 1, offset))
    return str(hosts[index])


def _enrich_sim_system_network(sim_system: Dict[str, Any]) -> None:
    variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
    ip_counters: Dict[str, int] = {}

    for var_id, info in variables.items():
        info = info if isinstance(info, dict) else {}
        domain = classify_domain(str(var_id), info)
        if domain != "cyber":
            continue

        label = str(info.get("name") or info.get("label") or var_id)
        role = str(info.get("type") or info.get("role") or "")

        purdue = info.get("purdue_level") or info.get("purdue") or _infer_purdue(label, role)
        if purdue:
            info["purdue_level"] = purdue

        vlan_cidr = info.get("vlan_cidr") or info.get("subnet") or info.get("cidr")
        if not vlan_cidr and purdue:
            vlan_cidr = DEFAULT_PURDUE_SUBNETS.get(purdue)
        if vlan_cidr:
            info["vlan_cidr"] = vlan_cidr

        if not info.get("vlan") and purdue:
            info["vlan"] = purdue

        if not extract_ip(info) and vlan_cidr:
            info["ip"] = _next_ip(vlan_cidr, ip_counters)

        variables[var_id] = info


def upload_sim_system(sim_path: Path, target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sim_path, target_path)
    return target_path
