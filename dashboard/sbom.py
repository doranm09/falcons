import hashlib
import json
from typing import Any, Dict, List, Optional


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


def _normalize_cve_id(value: Optional[str]) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if text.upper().startswith("CVE-"):
        return text.upper()
    return text


def _extract_score(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_severity(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip().title()
    if text in {"Critical", "High", "Medium", "Low", "None"}:
        return text
    return text


def _extract_refs(item: Dict[str, Any]) -> str:
    refs = []
    for key in ("references", "reference", "url", "link"):
        val = item.get(key)
        if isinstance(val, list):
            refs.extend(str(entry) for entry in val if entry)
        elif val:
            refs.append(str(val))
    return ", ".join(sorted(set(refs)))


def _normalize_vulnerability_item(item: Any) -> Optional[Dict[str, Any]]:
    if isinstance(item, str):
        cve_id = _normalize_cve_id(item)
        if not cve_id:
            return None
        return {
            "cve_id": cve_id,
            "severity": "",
            "score": None,
            "description": "",
            "references": "",
        }

    if not isinstance(item, dict):
        return None

    cve_id = _normalize_cve_id(
        item.get("cve_id")
        or item.get("cve")
        or item.get("id")
        or item.get("vulnerabilityID")
        or item.get("vulnerabilityId")
        or item.get("cveId")
    )
    if not cve_id:
        return None

    score = _extract_score(
        item.get("cvss_score")
        or item.get("cvssScore")
        or item.get("score")
        or item.get("cvss")
    )
    severity = _extract_severity(item.get("severity") or item.get("cvssSeverity"))
    description = str(item.get("description") or item.get("title") or "").strip()

    return {
        "cve_id": cve_id,
        "severity": severity,
        "score": score,
        "description": description,
        "references": _extract_refs(item),
    }


def extract_vulnerabilities_from_sbom(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    vulnerabilities: List[Dict[str, Any]] = []
    raw_items: List[Any] = []

    vulnerabilities_payload = payload.get("vulnerabilities")
    if isinstance(vulnerabilities_payload, list):
        raw_items = vulnerabilities_payload
    elif isinstance(vulnerabilities_payload, dict):
        if isinstance(vulnerabilities_payload.get("vulnerabilities"), list):
            raw_items = vulnerabilities_payload.get("vulnerabilities", [])
        elif isinstance(vulnerabilities_payload.get("matches"), list):
            for match in vulnerabilities_payload.get("matches", []):
                if isinstance(match, dict) and isinstance(match.get("vulnerability"), dict):
                    raw_items.append(match.get("vulnerability"))
    elif isinstance(payload.get("matches"), list):
        for match in payload.get("matches", []):
            if isinstance(match, dict) and isinstance(match.get("vulnerability"), dict):
                raw_items.append(match.get("vulnerability"))

    for item in raw_items:
        normalized = _normalize_vulnerability_item(item)
        if normalized:
            vulnerabilities.append(normalized)

    return vulnerabilities
