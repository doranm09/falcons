import re
import copy
import uuid
from typing import Dict, Any

_PURL_NAME_ALLOWED = re.compile(r"[^a-z0-9.+\-_]")

def _slugify_for_purl(name: str) -> str:
    """
    Convert 'DisplayName' into a purl-safe package name:
    - lowercase
    - replace spaces, brackets, parens, pipes, etc. with '-'
    - collapse multiple dashes
    - trim leading/trailing dashes
    """
    s = (name or "").strip().lower()
    s = _PURL_NAME_ALLOWED.sub("-", s)      # replace invalid with '-'
    s = re.sub(r"-{2,}", "-", s)            # collapse ---
    return s.strip("-") or "unknown"

def _looks_like_valid_purl(purl: str) -> bool:
    # Very light sanity check for purl shape: pkg:type/name@version
    return bool(re.match(r"^pkg:[a-z][a-z0-9.+\-]*\/[A-Za-z0-9.+\-_.]+@[^@\s\/]+$", purl or ""))

def _make_windows_purl(name: str, version: str) -> str:
    slug = _slugify_for_purl(name)
    ver  = (version or "").strip() or "unknown"
    return f"pkg:windows/{slug}@{ver}"

def fix_windows_sbom(sbom: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a CycloneDX JSON SBOM (dict) produced from Windows inventory so Trivy can parse it.

    - Ensures bomFormat/specVersion/version/serialNumber
    - Ensures metadata.component 'operating-system' entry shape
    - For each component:
        * type defaults to 'application'
        * build/repair purl as pkg:windows/<slug>@<version>
        * set bom-ref to the purl
    Returns a NEW dict (does not mutate input).
    """
    fixed = copy.deepcopy(sbom)

    # Top-level required-ish fields
    fixed.setdefault("bomFormat", "CycloneDX")
    fixed.setdefault("specVersion", "1.6")
    fixed.setdefault("version", 1)
    fixed.setdefault("serialNumber", f"urn:uuid:{uuid.uuid4()}")

    # Metadata sanity
    md = fixed.setdefault("metadata", {})
    md.setdefault("tools", [])
    comp_os = md.get("component") or {}
    # Make sure metadata.component describes the OS in a simple way (optional but nice)
    if not comp_os or comp_os.get("type") != "operating-system":
        # Try to preserve any existing name/version if present
        name = (comp_os.get("name") if isinstance(comp_os, dict) else None) or "windows"
        version = (comp_os.get("version") if isinstance(comp_os, dict) else None) or ""
        md["component"] = {
            "type": "operating-system",
            "name": name,
            "version": version
        }

    # Fix components
    comps = fixed.setdefault("components", [])
    for c in comps:
        # Ensure type
        c.setdefault("type", "application")

        # Prefer the existing human-readable name/version as fields
        human_name = c.get("name") or "unknown"
        version    = (c.get("version") or "").strip() or "unknown"

        # Decide purl
        purl = c.get("purl")
        if not _looks_like_valid_purl(purl):
            purl = _make_windows_purl(human_name, version)
            c["purl"] = purl

        # bom-ref best practice: use purl (stable unique id)
        c["bom-ref"] = c.get("bom-ref") or purl

    return fixed