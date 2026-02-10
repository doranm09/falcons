from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any, Dict, Tuple

from django.utils.timezone import now

from knowledge_extraction.drawio import parse_drawio_sim_system, save_sim_system

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
    output_dir.mkdir(parents=True, exist_ok=True)
    sim_path = output_dir / f"{prefix}_sim_system.json"
    save_sim_system(sim_path, sim_system)
    return sim_system, sim_path


def upload_sim_system(sim_path: Path, target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sim_path, target_path)
    return target_path
