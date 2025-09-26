#!/usr/bin/env python3
# sbom_fix_windows.py
import sys, json, argparse, uuid
from urllib.parse import quote

KNOWN_PURL_TYPES = {
    "alpm","apk","bitbucket","cargo","cocoapods","composer","conan","conda",
    "cran","deb","docker","gem","generic","github","golang","hackage","hex",
    "maven","npm","nuget","oci","pub","pypi","rpm","swift"
}

def needs_windows_fix(purl: str|None, comp: dict) -> bool:
    """
    Heuristics:
    - No purl at all -> fix
    - purl type 'rpm' with a 'windows' namespace -> fix
    - purl contains spaces or parentheses unencoded -> fix
    - purl type not recognized -> fix
    """
    if not purl:
        return True
    if " " in purl or "(" in purl or ")" in purl:
        return True
    try:
        if not purl.startswith("pkg:"):
            return True
        body = purl[4:]
        typ, rest = body.split("/", 1)
        if typ not in KNOWN_PURL_TYPES:
            return True
        # rpm + windows namespace is a dead giveaway
        if typ == "rpm" and rest.lower().startswith("windows/"):
            return True
    except Exception:
        return True
    return False

def build_generic_windows_purl(name: str, version: str|None, arch_hint: str|None=None) -> str:
    # URL-encode name and version per package-url rules
    n = quote(name, safe="")            # encode everything that isn't unreserved
    v = quote(version, safe="") if version else None
    qualifiers = []
    qualifiers.append("os=windows")
    if arch_hint:
        qualifiers.append(f"arch={quote(arch_hint, safe='')}")
    q = "?" + "&".join(qualifiers) if qualifiers else ""
    return f"pkg:generic/{n}@{v}{q}" if v else f"pkg:generic/{n}{q}"

def guess_arch(name: str) -> str|None:
    low = name.lower()
    if "x64" in low or " 64-bit" in low or " (64-bit" in low or "amd64" in low:
        return "x64"
    if "x86" in low or " 32-bit" in low or " (32-bit" in low or "win32" in low:
        return "x86"
    if "arm64" in low or " aarch64" in low:
        return "arm64"
    return None

def fix_component(comp: dict) -> dict:
    # Ensure required fields
    name = comp.get("name", "").strip()
    version = (comp.get("version") or "").strip()
    purl = comp.get("purl")
    if needs_windows_fix(purl, comp):
        arch = guess_arch(name)
        new_purl = build_generic_windows_purl(name=name, version=version or None, arch_hint=arch)
        comp["purl"] = new_purl
    # bom-ref should be stable and URI-safe. Reuse purl if present; else synthesize.
    if not comp.get("bom-ref"):
        comp["bom-ref"] = comp["purl"] if comp.get("purl") else f"urn:uuid:{uuid.uuid4()}"
    return comp

def ensure_metadata(bom: dict) -> None:
    bom.setdefault("metadata", {})
    md = bom["metadata"]
    # specVersion defaults
    if "specVersion" not in bom:
        bom["specVersion"] = "1.6"
    # Optional: nothing else mandatory here for CycloneDX JSON

def main():
    ap = argparse.ArgumentParser(description="Fix Windows SBOM purls/bom-refs for CycloneDX JSON")
    ap.add_argument("input", nargs="?", help="Input SBOM JSON file (defaults to stdin)")
    ap.add_argument("-o", "--output", help="Output file (defaults to stdout)")
    ap.add_argument("--only-windows", action="store_true",
                    help="Only fix when metadata.component.type==operating-system and name contains 'windows'")
    args = ap.parse_args()

    data = sys.stdin.read() if not args.input else open(args.input, "r", encoding="utf-8").read()
    try:
        bom = json.loads(data)
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Optionally gate on OS=windows in metadata
    if args.only_windows:
        meta_comp = (((bom.get("metadata") or {}).get("component")) or {})
        os_name = str(meta_comp.get("name", "")).lower()
        os_type = str(meta_comp.get("type", "")).lower()
        if not (os_type == "operating-system" and "windows" in os_name):
            # Nothing to do
            out = json.dumps(bom, indent=2, ensure_ascii=False)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out + "\n")
            else:
                print(out)
            return

    # serialNumber is optional but helpful (Trivy likes it). Generate if missing.
    if not bom.get("serialNumber"):
        bom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"

    ensure_metadata(bom)

    comps = bom.get("components")
    if isinstance(comps, list):
        for i, c in enumerate(comps):
            if isinstance(c, dict):
                comps[i] = fix_component(c)

    out = json.dumps(bom, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)

if __name__ == "__main__":
    main()
