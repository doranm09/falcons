import ast
import hashlib
import json
import re
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


def _coerce_mapping(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") and text.endswith("}"):
            try:
                parsed = ast.literal_eval(text)
            except (SyntaxError, ValueError):
                return None
            if isinstance(parsed, dict):
                return parsed
    return None


def _coerce_mapping(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") and text.endswith("}"):
            try:
                parsed = ast.literal_eval(text)
            except (SyntaxError, ValueError):
                return None
            if isinstance(parsed, dict):
                return parsed
    return None


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


def extract_package_dicts_from_sbom(payload: Any) -> List[Dict[str, Any]]:
    packages: List[Dict[str, Any]] = []

    def _normalize_package(item: Any) -> Optional[Dict[str, Any]]:
        mapped = _coerce_mapping(item)
        if mapped:
            return {
                "name": mapped.get("name") or mapped.get("package") or mapped.get("bom-ref") or mapped.get("purl") or "unknown",
                "version": mapped.get("version") or "",
                "type": mapped.get("type") or mapped.get("pkg_type") or "package",
                "purl": mapped.get("purl") or mapped.get("bom-ref") or "",
                "bom-ref": mapped.get("bom-ref") or "",
                "scope": mapped.get("scope") or "",
                "licenses": mapped.get("licenses") or [],
                "description": mapped.get("description") or mapped.get("summary") or "",
            }

        text = str(item or "").strip()
        if not text:
            return None
        name = text
        version = ""
        if "@" in text:
            candidate_name, candidate_version = text.rsplit("@", 1)
            if candidate_name and candidate_version:
                name = candidate_name
                version = candidate_version
        return {
            "name": name,
            "version": version,
            "type": "package",
            "purl": "",
            "bom-ref": "",
            "scope": "",
            "licenses": [],
            "description": "",
        }

    if isinstance(payload, dict):
        if isinstance(payload.get("components"), list):
            for item in payload.get("components", []):
                package = _normalize_package(item)
                if package:
                    packages.append(package)
        elif isinstance(payload.get("packages"), list):
            for item in payload.get("packages", []):
                package = _normalize_package(item)
                if package:
                    packages.append(package)
    elif isinstance(payload, list):
        for item in payload:
            package = _normalize_package(item)
            if package:
                packages.append(package)

    return packages


def extract_sbom_table_rows(payload: Any) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []

    def _licenses_to_text(component: Dict[str, Any]) -> str:
        licenses = component.get("licenses")
        if not isinstance(licenses, list):
            return ""
        parts: List[str] = []
        for license_item in licenses:
            if not isinstance(license_item, dict):
                continue
            lic = license_item.get("license")
            if isinstance(lic, dict):
                name = lic.get("name") or lic.get("id") or ""
                if name:
                    parts.append(str(name))
            else:
                name = license_item.get("name") or license_item.get("id") or ""
                if name:
                    parts.append(str(name))
        return ", ".join(dict.fromkeys(parts))

    def _append_row(component: Dict[str, Any]) -> None:
        name = (
            component.get("name")
            or component.get("bom-ref")
            or component.get("purl")
            or "Unknown"
        )
        rows.append(
            {
                "name": str(name),
                "version": str(component.get("version") or ""),
                "type": str(component.get("type") or ""),
                "scope": str(component.get("scope") or ""),
                "purl": str(component.get("purl") or ""),
                "bom_ref": str(component.get("bom-ref") or ""),
                "licenses": _licenses_to_text(component),
                "description": str(component.get("description") or ""),
            }
        )

    if isinstance(payload, dict):
        if isinstance(payload.get("components"), list):
            for component in payload.get("components", []):
                if isinstance(component, dict):
                    _append_row(component)
                else:
                    rows.append(
                        {
                            "name": str(component),
                            "version": "",
                            "type": "",
                            "scope": "",
                            "purl": "",
                            "bom_ref": "",
                            "licenses": "",
                            "description": "",
                        }
                    )
        elif isinstance(payload.get("packages"), list):
            for item in payload.get("packages", []):
                if isinstance(item, dict):
                    _append_row(item)
                else:
                    rows.append(
                        {
                            "name": str(item),
                            "version": "",
                            "type": "",
                            "scope": "",
                            "purl": "",
                            "bom_ref": "",
                            "licenses": "",
                            "description": "",
                        }
                    )
    elif isinstance(payload, list):
        for item in payload:
            rows.append(
                {
                    "name": str(item),
                    "version": "",
                    "type": "",
                    "scope": "",
                    "purl": "",
                    "bom_ref": "",
                    "licenses": "",
                    "description": "",
                }
            )

    return rows


def extract_cyber_template_table_rows(packages: Any) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []

    def _append_package_row(package: Any) -> None:
        package_dict = _coerce_mapping(package)
        if package_dict:
            licenses = package_dict.get("licenses")
            license_text = ""
            if isinstance(licenses, list):
                parts: List[str] = []
                for license_item in licenses:
                    if isinstance(license_item, dict):
                        lic = license_item.get("license")
                        if isinstance(lic, dict):
                            name = lic.get("name") or lic.get("id") or ""
                        else:
                            name = license_item.get("name") or license_item.get("id") or ""
                        if name:
                            parts.append(str(name))
                    elif license_item:
                        parts.append(str(license_item))
                license_text = ", ".join(dict.fromkeys(parts))
            elif licenses:
                license_text = str(licenses)

            rows.append(
                {
                    "name": str(
                        package_dict.get("name")
                        or package_dict.get("package")
                        or package_dict.get("bom-ref")
                        or package_dict.get("purl")
                        or "Unknown"
                    ),
                    "version": str(package_dict.get("version") or ""),
                    "type": str(package_dict.get("type") or package_dict.get("pkg_type") or "package"),
                    "scope": str(package_dict.get("scope") or ""),
                    "purl": str(package_dict.get("purl") or package_dict.get("bom-ref") or ""),
                    "bom_ref": str(package_dict.get("bom-ref") or ""),
                    "licenses": license_text,
                    "description": str(package_dict.get("description") or package_dict.get("summary") or ""),
                }
            )
            return

        text = str(package or "").strip()
        if not text:
            return
        name = text
        version = ""
        if "@" in text:
            candidate_name, candidate_version = text.rsplit("@", 1)
            if candidate_name and candidate_version:
                name = candidate_name
                version = candidate_version
        rows.append(
            {
                "name": name,
                "version": version,
                "type": "package",
                "scope": "",
                "purl": "",
                "bom_ref": "",
                "licenses": "",
                "description": "",
            }
        )

    if isinstance(packages, list):
        for package in packages:
            _append_package_row(package)
    elif isinstance(packages, dict) and isinstance(packages.get("packages"), list):
        for package in packages.get("packages", []):
            if isinstance(package, dict):
                _append_package_row(package.get("name") or package.get("purl") or package.get("bom-ref") or "")
            else:
                _append_package_row(package)

    return rows


def extract_vulnerability_table_rows_from_models(vulnerabilities: Any) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    if vulnerabilities is None:
        return rows

    for vuln in vulnerabilities:
        if not vuln:
            continue
        rows.append(
            {
                "cve_id": str(getattr(vuln, "cve_id", "") or ""),
                "severity": str(getattr(vuln, "severity", "") or ""),
                "score": "" if getattr(vuln, "score", None) is None else str(getattr(vuln, "score")),
                "package": str(getattr(vuln, "package", "") or ""),
                "installed_version": str(getattr(vuln, "installed_version", "") or ""),
                "fixed_version": str(getattr(vuln, "fixed_version", "") or ""),
                "source": str(getattr(vuln, "source", "") or ""),
                "description": str(getattr(vuln, "description", "") or ""),
                "references": str(getattr(vuln, "references", "") or ""),
            }
        )

    return rows


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


def infer_grype_distro(payload: Any, os_summary: str = "") -> str:
    candidates = [str(os_summary or "").strip(), extract_os_summary_from_sbom(payload)]
    distro_aliases = {
        "debian": ("debian",),
        "ubuntu": ("ubuntu",),
        "alpine": ("alpine",),
        "rocky": ("rocky", "rocky linux"),
        "alma": ("alma", "alma linux", "almalinux"),
        "rhel": ("rhel", "red hat enterprise linux", "red hat"),
        "centos": ("centos",),
        "amzn": ("amazon linux", "amzn"),
    }

    for raw_text in candidates:
        text = str(raw_text or "").strip().lower()
        if not text:
            continue
        version_match = re.search(r"\b(\d+(?:\.\d+)?)\b", text)
        if not version_match:
            continue
        version = version_match.group(1)
        for grype_name, aliases in distro_aliases.items():
            if any(alias in text for alias in aliases):
                return f"{grype_name}:{version}"
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
    if isinstance(value, dict):
        return _extract_score(
            value.get("baseScore")
            or value.get("score")
            or value.get("metrics")
            or value.get("cvss")
        )
    if isinstance(value, list):
        scores = [score for score in (_extract_score(entry) for entry in value) if score is not None]
        return max(scores) if scores else None
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
    for key in ("references", "reference", "url", "link", "PrimaryURL", "PrimaryUrl", "Links", "links"):
        val = item.get(key)
        if isinstance(val, list):
            refs.extend(str(entry) for entry in val if entry)
        elif val:
            refs.append(str(val))
    urls = item.get("urls")
    if isinstance(urls, list):
        refs.extend(str(entry) for entry in urls if entry)
    elif urls:
        refs.append(str(urls))
    return ", ".join(sorted(set(refs)))


def _extract_fixed_versions(item: Dict[str, Any]) -> str:
    direct_value = (
        item.get("fixed_version")
        or item.get("FixedVersion")
        or item.get("fix_version")
        or item.get("Fixed")
    )
    if direct_value:
        return str(direct_value).strip()

    fix = item.get("fix")
    if isinstance(fix, dict):
        versions = fix.get("versions")
        if isinstance(versions, list):
            normalized = [str(version).strip() for version in versions if str(version).strip()]
            if normalized:
                return ", ".join(normalized)

    related = item.get("relatedVulnerabilities")
    if isinstance(related, list):
        for related_item in related:
            if not isinstance(related_item, dict):
                continue
            nested_fix = _extract_fixed_versions(related_item)
            if nested_fix:
                return nested_fix

    return ""


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
            "package": "",
            "installed_version": "",
            "fixed_version": "",
            "source": "",
        }

    if not isinstance(item, dict):
        return None

    cve_id = _normalize_cve_id(
        item.get("cve_id")
        or item.get("cve")
        or item.get("id")
        or item.get("VulnerabilityID")
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
        or item.get("CVSS")
        or item.get("relatedVulnerabilities")
    )
    severity = _extract_severity(
        item.get("severity")
        or item.get("Severity")
        or item.get("cvssSeverity")
    )
    description = str(
        item.get("description")
        or item.get("Description")
        or item.get("title")
        or item.get("Title")
        or ""
    ).strip()
    artifact = item.get("artifact") if isinstance(item.get("artifact"), dict) else {}

    return {
        "cve_id": cve_id,
        "severity": severity,
        "score": score,
        "description": description,
        "references": _extract_refs(item),
        "package": str(
            item.get("pkg_name")
            or item.get("PkgName")
            or item.get("name")
            or item.get("artifact_name")
            or (artifact.get("name") if artifact else "")
            or ""
        ).strip(),
        "installed_version": str(
            item.get("installed_version")
            or item.get("InstalledVersion")
            or item.get("version")
            or item.get("artifact_version")
            or (artifact.get("version") if artifact else "")
            or ""
        ).strip(),
        "fixed_version": _extract_fixed_versions(item),
        "source": str(
            item.get("source")
            or item.get("dataSource")
            or item.get("datasource")
            or item.get("namespace")
            or ""
        ).strip(),
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
                    merged = dict(match.get("vulnerability"))
                    if isinstance(match.get("artifact"), dict):
                        artifact = match.get("artifact")
                        merged.setdefault("artifact", artifact)
                        merged.setdefault("pkg_name", artifact.get("name"))
                        merged.setdefault("installed_version", artifact.get("version"))
                    raw_items.append(merged)
    elif isinstance(payload.get("matches"), list):
        for match in payload.get("matches", []):
            if isinstance(match, dict) and isinstance(match.get("vulnerability"), dict):
                merged = dict(match.get("vulnerability"))
                if isinstance(match.get("artifact"), dict):
                    artifact = match.get("artifact")
                    merged.setdefault("artifact", artifact)
                    merged.setdefault("pkg_name", artifact.get("name"))
                    merged.setdefault("installed_version", artifact.get("version"))
                raw_items.append(merged)
    elif isinstance(payload.get("Results"), list):
        for result in payload.get("Results", []):
            if not isinstance(result, dict):
                continue
            for vuln in result.get("Vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                merged = dict(vuln)
                merged.setdefault("source", result.get("Target") or result.get("Class") or "")
                merged.setdefault("pkg_name", vuln.get("PkgName"))
                merged.setdefault("installed_version", vuln.get("InstalledVersion"))
                merged.setdefault("fixed_version", vuln.get("FixedVersion"))
                raw_items.append(merged)

    for item in raw_items:
        normalized = _normalize_vulnerability_item(item)
        if normalized:
            vulnerabilities.append(normalized)

    return vulnerabilities


def extract_vulnerability_table_rows(payload: Any) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for vuln in extract_vulnerabilities_from_sbom(payload):
        score = vuln.get("score")
        rows.append(
            {
                "cve_id": str(vuln.get("cve_id") or ""),
                "severity": str(vuln.get("severity") or ""),
                "score": "" if score is None else str(score),
                "package": str(vuln.get("package") or ""),
                "installed_version": str(vuln.get("installed_version") or ""),
                "fixed_version": str(vuln.get("fixed_version") or ""),
                "source": str(vuln.get("source") or ""),
                "description": str(vuln.get("description") or ""),
                "references": str(vuln.get("references") or ""),
            }
        )
    return rows
