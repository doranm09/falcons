import hashlib
import json
from typing import Any, Dict, List


def compute_payload_hash(payload: Any) -> str:
    try:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except TypeError:
        serialized = json.dumps(str(payload))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _component_to_package(component: Dict[str, Any]) -> str:
    name = component.get("name") or component.get("purl") or component.get("bom-ref")
    version = component.get("version")
    if not name:
        return ""
    return f"{name}@{version}" if version else name


def extract_packages_from_sbom(payload: Any) -> List[str]:
    packages: List[str] = []

    if isinstance(payload, dict):
        if isinstance(payload.get("components"), list):
            for component in payload.get("components", []):
                if isinstance(component, dict):
                    pkg = _component_to_package(component)
                    if pkg:
                        packages.append(pkg)
                else:
                    packages.append(str(component))
        elif isinstance(payload.get("packages"), list):
            for item in payload.get("packages", []):
                if isinstance(item, dict):
                    pkg = _component_to_package(item) or item.get("name") or ""
                    if pkg:
                        packages.append(pkg)
                else:
                    packages.append(str(item))
    elif isinstance(payload, list):
        packages = [str(item) for item in payload]

    return packages


def extract_os_summary_from_sbom(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""

    metadata = payload.get("metadata") or {}
    component = metadata.get("component") or {}
    if isinstance(component, dict):
        comp_type = component.get("type", "").lower()
        if comp_type in {"operating-system", "os"}:
            name = component.get("name") or ""
            version = component.get("version") or ""
            return f"{name} {version}".strip()

    for component in payload.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        comp_type = component.get("type", "").lower()
        if comp_type in {"operating-system", "os"}:
            name = component.get("name") or ""
            version = component.get("version") or ""
            return f"{name} {version}".strip()

    return ""


def detect_sbom_format(payload: Any) -> Dict[str, str]:
    if not isinstance(payload, dict):
        return {"format": "raw", "bom_format": "", "spec_version": ""}

    bom_format = payload.get("bomFormat", "")
    spec_version = payload.get("specVersion", "")
    if bom_format or spec_version:
        return {
            "format": "cyclonedx",
            "bom_format": str(bom_format),
            "spec_version": str(spec_version),
        }

    return {"format": "raw", "bom_format": "", "spec_version": ""}
