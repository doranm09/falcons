#!/usr/bin/env python3
# fix_windows_sbom.py
import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests  # optional, only if --post is used
except Exception:
    requests = None

CYCLONEDX_SPEC = "1.6"

# characters commonly present in Windows DisplayName that break purls
# we'll normalize to a slug; keep alnum, dash, underscore, dot
_slug_re = re.compile(r"[^a-z0-9._-]+")

def now_iso_z():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def slugify_name(name: str) -> str:
    """
    Produce a conservative purl-safe slug from an arbitrary Windows DisplayName.
    Lowercase, replace spaces and punctuation with single '-'.
    """
    name = (name or "").strip().lower()
    # common cleanups
    # collapse special tokens like " | " that appear in product titles
    name = name.replace("|", "-").replace("–", "-").replace("—", "-")
    name = name.replace("&", "and").replace("+", "plus")
    name = name.replace("®", "").replace("™", "")
    name = _slug_re.sub("-", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name or "unknown"

def clean_version(version: str) -> str:
    return (version or "").strip()

def ensure_bom_base(doc: dict, os_name: str, os_version: str, tool_vendor: str, tool_name: str, tool_version: str) -> None:
    doc["bomFormat"] = "CycloneDX"
    doc["specVersion"] = CYCLONEDX_SPEC
    if not isinstance(doc.get("version"), int):
        doc["version"] = 1
    # serialNumber must be a URN with UUID (CycloneDX)
    sn = doc.get("serialNumber")
    try:
        if not (isinstance(sn, str) and sn.startswith("urn:uuid:") and uuid.UUID(sn.split("urn:uuid:")[-1])):
            raise ValueError()
    except Exception:
        doc["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"

    md = doc.setdefault("metadata", {})
    md.setdefault("timestamp", now_iso_z())
    comp = md.setdefault("component", {})
    if not comp:
        md["component"] = comp = {}
    comp.setdefault("type", "operating-system")
    comp["name"] = os_name or comp.get("name") or "windows"
    comp["version"] = os_version or comp.get("version") or "unknown"

    tools = md.setdefault("tools", [])
    # ensure our fixer tool is present (dedup on name/vendor)
    already = any(
        (isinstance(t, dict) and t.get("name") == tool_name and t.get("vendor") == tool_vendor)
        for t in tools
    )
    if not already:
        tools.append({"vendor": tool_vendor, "name": tool_name, "version": tool_version})

def build_generic_purl(name: str, version: str) -> str:
    """
    Build a pkg:generic PURL. We use a conservative slug for the name to avoid parser issues.
    """
    slug = slugify_name(name)
    # per PURL spec, name should be URL-encoded if it had reserved chars; slug avoids most
    # still defend by quoting any leftover
    safe_name = quote(slug, safe="._-") or "unknown"
    ver = clean_version(version) or "unknown"
    return f"pkg:generic/{safe_name}@{ver}"

def fix_components(doc: dict, drop_empty: bool = True) -> int:
    comps = doc.setdefault("components", [])
    if not isinstance(comps, list):
        # If components is malformed, reset to list
        comps = []
        doc["components"] = comps
        return 0

    fixed = 0
    new_list = []
    for c in comps:
        if not isinstance(c, dict):
            continue
        name = (c.get("name") or "").strip()
        version = clean_version(c.get("version") or "")
        if drop_empty and not name:
            continue

        # Make sure component is an application for Windows entries
        c["type"] = c.get("type") or "application"

        # Repair purl if missing/invalid or obviously not purl-safe
        purl = c.get("purl")
        replace_purl = True
        if isinstance(purl, str) and purl.startswith("pkg:"):
            # lightweight validation: must have '@version' and a name after scheme
            replace_purl = ("@" not in purl) or (purl.count("/") < 1)

        if replace_purl:
            purl = build_generic_purl(name, version)
            c["purl"] = purl

        # bom-ref should be stable and unique per component; using purl is compliant
        c["bom-ref"] = c.get("bom-ref") or purl

        # Normalize display-ish name: trim whitespace
        c["name"] = name

        # Remove obviously empty fields some tools choke on
        for k in list(c.keys()):
            if c[k] in (None, "", []):
                del c[k]

        new_list.append(c)
        fixed += 1

    doc["components"] = new_list
    return fixed

def post_if_requested(url: str, sbom: dict, agent_id: str = None) -> None:
    if not url:
        return
    if requests is None:
        raise RuntimeError("requests is not installed; cannot POST")
    headers = {"Content-Type": "application/json"}
    if agent_id:
        headers["X-Agent-ID"] = agent_id
    headers["X-Timestamp"] = now_iso_z()
    r = requests.post(url, headers=headers, data=json.dumps(sbom))
    r.raise_for_status()

def main():
    ap = argparse.ArgumentParser(
        description="Fix/normalize Windows-collected CycloneDX SBOMs for better tool compatibility (e.g., Trivy)."
    )
    ap.add_argument("input", nargs="?", help="Input SBOM file (JSON). If omitted, reads stdin.")
    ap.add_argument("-o", "--output", help="Output file (JSON). If omitted, writes to stdout.")
    ap.add_argument("--os-name", default="windows", help="Override OS name in metadata.component (default: windows)")
    ap.add_argument("--os-version", default=None, help="Override OS version in metadata.component")
    ap.add_argument("--tool-vendor", default="custom", help="Tool vendor to add into metadata.tools")
    ap.add_argument("--tool-name", default="sbom-fixer", help="Tool name to add into metadata.tools")
    ap.add_argument("--tool-version", default="0.1.0", help="Tool version to add into metadata.tools")
    ap.add_argument("--no-drop-empty", action="store_true", help="Do not drop components with empty names")
    ap.add_argument("--post", metavar="URL", help="POST the fixed SBOM to a URL after writing")
    ap.add_argument("--agent-id", help="Optional X-Agent-ID header when posting")
    args = ap.parse_args()

    # Load input
    data: dict
    try:
        if args.input:
            with open(args.input, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.load(sys.stdin)
    except Exception as e:
        print(f"[error] Failed to read input: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(data, dict):
        print("[error] Input is not a JSON object", file=sys.stderr)
        sys.exit(2)

    # Fix top-level + components
    ensure_bom_base(
        data,
        os_name=args.os_name,
        os_version=args.os_version or data.get("metadata", {}).get("component", {}).get("version") or "unknown",
        tool_vendor=args.tool_vendor,
        tool_name=args.tool_name,
        tool_version=args.tool_version,
    )
    fixed_count = fix_components(data, drop_empty=not args.no_drop_empty)

    # Write output
    try:
        out_json = json.dumps(data, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_json)
        else:
            print(out_json)
    except Exception as e:
        print(f"[error] Failed to write output: {e}", file=sys.stderr)
        sys.exit(3)

    # Optional POST
    if args.post:
        try:
            post_if_requested(args.post, data, agent_id=args.agent_id)
        except Exception as e:
            print(f"[warn] POST failed: {e}", file=sys.stderr)

    print(f"[ok] Fixed SBOM with {fixed_count} components", file=sys.stderr)

if __name__ == "__main__":
    main()
