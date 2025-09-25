#!/usr/bin/env python3
"""
sbom_fix_windows_all_cpe.py — Fix a CycloneDX JSON SBOM of Windows installed apps
and add CPEs for EVERY component (official where known, synthetic otherwise).

What it does:
  • Clean component "name" (strip arch/host text; remove embedded versions)
  • Keep version in "version" (infer from name if missing)
  • Replace odd purls with pkg:generic/<slug>@<version>
  • Set bom-ref = purl
  • Add cpe for every component:
      - prefer curated mapping (safer names that vuln DBs recognize)
      - otherwise synthesize vendor/product from the cleaned name
  • Preserve the original name via properties[name=original:name]

Usage:
  python3 sbom_fix_windows_all_cpe.py INPUT.json [-o OUTPUT.json] [--in-place] [--verbose]
"""

import argparse, json, re, sys, urllib.parse
from pathlib import Path
from typing import Dict, Optional, Tuple

# ---------- Normalization helpers ----------

ARCH_HINTS = [
    r"\(x64 edition\)", r"\(64-bit x64\)", r"\(64-bit\)", r"\(x64\)", r"\(x86\)",
    r"\(arm64\)", r"\(arm\)", r"\(amd64\)"
]
BRACKET_BLOCK = r"\[[^\]]+\]"  # [remote.host] [ABC123]
WS = re.compile(r"\s+")

VERSION_PATTERNS = [
    r"\d+\.\d+\.\d+\.\d+",
    r"\d+\.\d+\.\d+",
    r"\d+\.\d+(?:\.\d+)?[.-]\d+",
    r"\d+\.\d+",
]

def normalize_name(raw: str) -> str:
    n = raw or ""
    n = re.sub(BRACKET_BLOCK, " ", n)
    for h in ARCH_HINTS:
        n = re.sub(h, " ", n, flags=re.IGNORECASE)
    n = n.replace("|", " ")   # “Dell Command | Update”
    n = re.sub(r"[_/]+", " ", n)
    n = WS.sub(" ", n).strip()
    return n

def extract_version_from_name(n: str) -> Optional[str]:
    for pat in VERSION_PATTERNS:
        m = re.search(pat, n)
        if m:
            return m.group(0)
    return None

def base_name_without_version(n: str) -> str:
    base = re.sub(r"\s+\d[\w\.\-]*$", "", n)  # drop trailing version-y token
    base = re.sub(r"\brelease$", "", base, flags=re.IGNORECASE).strip()
    return WS.sub(" ", base).strip(" -")

def slugify_name_for_purl(name: str) -> str:
    n = name.lower()
    n = re.sub(r"[^\w]+", "-", n)
    n = re.sub(r"-{2,}", "-", n).strip("-")
    return n or "unknown"

# ---------- CPE building ----------

def cpe_sanitize(s: str) -> str:
    """
    Basic CPE 'product'/'vendor' sanitization:
      - lowercase
      - spaces/punct -> underscore
      - collapse repeats
    (Not full WFN escaping, but safe and consistent for scanners that accept text form.)
    """
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "unknown"

def build_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

# Known, higher-confidence vendor/product mappings (normalized base name -> (vendor, product))
KNOWN_CPE: Dict[str, Tuple[str, str]] = {
    # General apps
    "7-zip": ("7-zip", "7-zip"),
    "git": ("git-scm", "git"),
    "google chrome": ("google", "chrome"),
    "microsoft edge": ("microsoft", "edge"),
    "microsoft edge webview2 runtime": ("microsoft", "edge_webview2"),
    "microsoft onedrive": ("microsoft", "onedrive"),
    "microsoft visual studio code": ("microsoft", "visual_studio_code"),
    "notepad++": ("don_ho", "notepad++"),
    "winscp": ("winscp", "winscp"),
    "putty": ("putty", "putty"),
    "zoom": ("zoom", "zoom"),
    "dropbox": ("dropbox", "dropbox"),
    "adobe acrobat": ("adobe", "acrobat"),
    "adobe creative cloud": ("adobe", "creative_cloud"),
    "adobe genuine service": ("adobe", "genuine_service"),
    "adobe refresh manager": ("adobe", "refresh_manager"),
    "crashplan": ("code42", "crashplan"),
    "globalprotect": ("palo_alto_networks", "globalprotect"),
    "cortex xdr": ("palo_alto_networks", "cortex_xdr_agent"),
    "endnote": ("clarivate", "endnote"),
    "anaconda3": ("anaconda", "anaconda"),
    "dell command update": ("dell", "command_update"),

    # Citrix (group under workspace app family unless clearly different)
    "citrix workspace": ("citrix", "workspace_app"),
    "citrix workspace inside": ("citrix", "workspace_app"),
    "citrix workspace dv": ("citrix", "workspace_app"),
    "citrix web helper": ("citrix", "workspace_app"),
    "self-service plug-in": ("citrix", "workspace_app"),
    "online plug-in": ("citrix", "workspace_app"),
    "bcr plug-in": ("citrix", "workspace_app"),
    "mtop client": ("citrix", "workspace_app"),
    "citrix authentication manager": ("citrix", "authentication_manager"),

    # NVIDIA
    "nvidia graphics driver": ("nvidia", "gpu_display_driver"),
    "nvidia install application": ("nvidia", "installer"),

    # Microsoft dev tools families (approximate but consistent)
    "visual studio community": ("microsoft", "visual_studio"),
    "vs jit debugger": ("microsoft", "visual_studio_jit_debugger"),
    "vs script debugging common": ("microsoft", "visual_studio_script_debugging"),
    "microsoft visual studio installer": ("microsoft", "visual_studio_installer"),
    "microsoft visual studio setup configuration": ("microsoft", "visual_studio_setup_configuration"),
    "microsoft visual studio setup wmi provider": ("microsoft", "visual_studio_setup_wmi_provider"),
    "vs filetracker singleton": ("microsoft", "visual_studio"),
    "vs graphics singletonx64": ("microsoft", "visual_studio_graphics_tools"),
    "vs graphics singletonx86": ("microsoft", "visual_studio_graphics_tools"),
    "vs communityx64msi": ("microsoft", "visual_studio"),
    "vs communitysharedmsi": ("microsoft", "visual_studio"),
    "vs communitymsires": ("microsoft", "visual_studio"),
    "vs devenx64vmsi": ("microsoft", "visual_studio"),
    "vs devenvsharedmsi": ("microsoft", "visual_studio"),
    "vs filehandler x86": ("microsoft", "visual_studio_filehandler"),
    "vs filehandler_amd64": ("microsoft", "visual_studio_filehandler"),
    "vs minshellx64msi": ("microsoft", "visual_studio"),
    "vs minshellinteropx64msi": ("microsoft", "visual_studio"),
    "vs minshellsharedmsi": ("microsoft", "visual_studio"),
    "vs minshellmsires": ("microsoft", "visual_studio"),
    "vs minshellinteropsharedmsi": ("microsoft", "visual_studio"),
    "vs tipsmsi": ("microsoft", "visual_studio"),
    "vs vswebprotocolselectormsi": ("microsoft", "visual_studio_web_protocol_selector"),
    "vs coreeditorfonts": ("microsoft", "visual_studio_core_editor_fonts"),
    "visual studio community 2022": ("microsoft", "visual_studio"),

    # SDKs, WPT, Windows tooling (coarse but consistent)
    "windows sdk": ("microsoft", "windows_sdk"),
    "windows sdk addon": ("microsoft", "windows_sdk"),
    "windows sdk eula": ("microsoft", "windows_sdk"),
    "windows sdk redistributables": ("microsoft", "windows_sdk"),
    "windows sdk directx x64 remote": ("microsoft", "windows_sdk_directx_remote"),
    "windows sdk directx x86 remote": ("microsoft", "windows_sdk_directx_remote"),
    "windows sdk desktop libs x64": ("microsoft", "windows_sdk_desktop_libs"),
    "windows sdk desktop libs x86": ("microsoft", "windows_sdk_desktop_libs"),
    "windows sdk desktop libs arm": ("microsoft", "windows_sdk_desktop_libs"),
    "windows sdk desktop libs arm64": ("microsoft", "windows_sdk_desktop_libs"),
    "windows sdk desktop headers x64": ("microsoft", "windows_sdk_desktop_headers"),
    "windows sdk desktop headers x86": ("microsoft", "windows_sdk_desktop_headers"),
    "windows sdk desktop headers arm": ("microsoft", "windows_sdk_desktop_headers"),
    "windows sdk desktop headers arm64": ("microsoft", "windows_sdk_desktop_headers"),
    "windows sdk desktop tools x64": ("microsoft", "windows_sdk_desktop_tools"),
    "windows sdk desktop tools x86": ("microsoft", "windows_sdk_desktop_tools"),
    "windows sdk arm desktop tools": ("microsoft", "windows_sdk_desktop_tools"),
    "windows sdk for windows store apps": ("microsoft", "windows_sdk_store_apps"),
    "windows sdk for windows store apps libs": ("microsoft", "windows_sdk_store_apps_libs"),
    "windows sdk for windows store apps headers": ("microsoft", "windows_sdk_store_apps_headers"),
    "windows sdk for windows store apps tools": ("microsoft", "windows_sdk_store_apps_tools"),
    "windows sdk for windows store apps metadata": ("microsoft", "windows_sdk_store_apps_metadata"),
    "windows sdk for windows store apps contracts": ("microsoft", "windows_sdk_store_apps_contracts"),
    "windows mobile extension sdk": ("microsoft", "windows_mobile_extension_sdk"),
    "windows mobile extension sdk contracts": ("microsoft", "windows_mobile_extension_sdk"),
    "windows iot extension sdk": ("microsoft", "windows_iot_extension_sdk"),
    "windows iot extension sdk contracts": ("microsoft", "windows_iot_extension_sdk"),
    "windows team extension sdk": ("microsoft", "windows_team_extension_sdk"),
    "windows team extension sdk contracts": ("microsoft", "windows_team_extension_sdk"),
    "windows desktop extension sdk": ("microsoft", "windows_desktop_extension_sdk"),
    "windows desktop extension sdk contracts": ("microsoft", "windows_desktop_extension_sdk"),
    "windows team extension sdk contracts": ("microsoft", "windows_team_extension_sdk"),
    "wptx64 onecoreuap": ("microsoft", "windows_performance_toolkit"),
    "wptx64 desktopeditions": ("microsoft", "windows_performance_toolkit"),
    "wpt redistributables": ("microsoft", "windows_performance_toolkit"),
    "windows app certification kit x64": ("microsoft", "windows_app_cert_kit"),
    "windows app certification kit x64 onecoreuap": ("microsoft", "windows_app_cert_kit"),
    "windows app certification kit native components": ("microsoft", "windows_app_cert_kit"),
    "windows app certification kit supportedapilist x86": ("microsoft", "windows_app_cert_kit"),
    "winappdeploy": ("microsoft", "winappdeploy"),
    "windows software development kit - windows": ("microsoft", "windows_sdk"),
    "kits configuration installer": ("microsoft", "windows_sdk"),
    "universal crt redistributable": ("microsoft", "universal_crt"),
    "universal crt tools x64": ("microsoft", "universal_crt_tools"),
    "universal crt tools x86": ("microsoft", "universal_crt_tools"),
    "universal crt extension sdk": ("microsoft", "universal_crt_extension_sdk"),
    "universal general midi dls extension sdk": ("microsoft", "universal_midi_dls_extension_sdk"),
    "universal crt headers libraries and sources": ("microsoft", "universal_crt_headers_libs_sources"),
    "windows sdk modern non-versioned developer tools": ("microsoft", "windows_sdk"),
    "windows sdk modern versioned developer tools": ("microsoft", "windows_sdk"),
    "windows sdk facade windows winmd versioned": ("microsoft", "windows_sdk_facade_winmd"),

    # Redistributables / Runtimes (approximate)
    "microsoft visual c++ 2010 x64 redistributable": ("microsoft", "visual_c++_2010_redistributable"),
    "microsoft visual c++ 2010 x86 redistributable": ("microsoft", "visual_c++_2010_redistributable"),
    "microsoft visual c++ 2012 x64 additional runtime": ("microsoft", "visual_c++_2012_runtime"),
    "microsoft visual c++ 2012 x64 minimum runtime": ("microsoft", "visual_c++_2012_runtime"),
    "microsoft visual c++ 2012 x86 additional runtime": ("microsoft", "visual_c++_2012_runtime"),
    "microsoft visual c++ 2012 x86 minimum runtime": ("microsoft", "visual_c++_2012_runtime"),
    "microsoft visual c++ 2012 redistributable x64": ("microsoft", "visual_c++_2012_redistributable"),
    "microsoft visual c++ 2012 redistributable x86": ("microsoft", "visual_c++_2012_redistributable"),
    "microsoft visual c++ 2013 x64 additional runtime": ("microsoft", "visual_c++_2013_runtime"),
    "microsoft visual c++ 2013 x64 minimum runtime": ("microsoft", "visual_c++_2013_runtime"),
    "microsoft visual c++ 2013 x86 additional runtime": ("microsoft", "visual_c++_2013_runtime"),
    "microsoft visual c++ 2013 x86 minimum runtime": ("microsoft", "visual_c++_2013_runtime"),
    "microsoft visual c++ 2013 redistributable x64": ("microsoft", "visual_c++_2013_redistributable"),
    "microsoft visual c++ 2013 redistributable x86": ("microsoft", "visual_c++_2013_redistributable"),
    "microsoft visual c++ 2015-2022 redistributable x64": ("microsoft", "visual_c++_2015-2022_redistributable"),
    "microsoft visual c++ 2015-2022 redistributable x86": ("microsoft", "visual_c++_2015-2022_redistributable"),
    "microsoft visual c++ 2022 x64 minimum runtime": ("microsoft", "visual_c++_2022_runtime"),
    "microsoft visual c++ 2022 x64 additional runtime": ("microsoft", "visual_c++_2022_runtime"),
    "microsoft visual c++ 2022 x64 debug runtime": ("microsoft", "visual_c++_2022_runtime"),
    "microsoft visual c++ 2022 x86 minimum runtime": ("microsoft", "visual_c++_2022_runtime"),
    "microsoft visual c++ 2022 x86 additional runtime": ("microsoft", "visual_c++_2022_runtime"),
    "microsoft visual c++ 2022 x86 debug runtime": ("microsoft", "visual_c++_2022_runtime"),

    # .NET
    "microsoft .net runtime - 6.0.36 x86": ("microsoft", "dotnet_runtime"),
    "microsoft .net host - 6.0.36 x86": ("microsoft", "dotnet_host"),
    "microsoft windows desktop runtime - 6.0.36 x86": ("microsoft", "dotnet_desktop_runtime"),
    "microsoft .net host fx resolver - 6.0.36 x86": ("microsoft", "dotnet_hostfx_resolver"),

    # MS platform bits
    "microsoft update health tools": ("microsoft", "update_health_tools"),
    "configuration manager client": ("microsoft", "configuration_manager_client"),
    "researchsoft direct export helper": ("clarivate", "endnote_direct_export_helper"),
    "microsoft policy platform": ("microsoft", "policy_platform"),
    "diagnosticshub_collectionservice": ("microsoft", "diagnosticshub_collectionservice"),
    "agent client collector": ("microsoft", "agent_client_collector"),  # best-effort
    "acronym:acrobat-x64-sdl": ("adobe", "acrobat_x64_sdl"),  # helper key (see canonicalize)
}

# Vendor hints for synthetic fallback
VENDOR_HINTS = [
    ("microsoft", ["microsoft", "windows", "visual studio", "vs ", "winrt", "wpt", "sdk"]),
    ("adobe", ["adobe", "acrobat"]),
    ("citrix", ["citrix"]),
    ("nvidia", ["nvidia"]),
    ("google", ["google", "chrome"]),
    ("dropbox", ["dropbox"]),
    ("zoom", ["zoom"]),
    ("palo_alto_networks", ["globalprotect", "cortex xdr", "palo alto"]),
    ("qualys", ["qualys"]),
    ("cyberark", ["cyberark"]),
    ("clarivate", ["endnote", "researchsoft"]),
    ("dell", ["dell"]),
    ("anaconda", ["anaconda"]),
    ("mathworks", ["matlab"]),
    ("git-scm", ["git"]),
    ("winscp", ["winscp"]),
    ("putty", ["putty"]),
    ("code42", ["crashplan"]),
]

def canonicalize_for_map(name: str, version: str) -> str:
    """
    Produce a key for KNOWN_CPE lookup.
    We keep it fairly literal but lowercase and compress spaces/punct.
    We also add a few special-case rewrites.
    """
    n = name.lower()
    n = n.replace("|", " ")
    n = re.sub(r"[^a-z0-9]+", " ", n)
    n = re.sub(r"\s+", " ", n).strip()

    # combine some tokens that show as separate
    if n.startswith("citrix workspace 2309"):
        n = "citrix workspace"
    if n == "visual studio community 2022":
        n = n  # already handled
    if n == "windows software development kit - windows":
        n = "windows software development kit - windows"

    # .NET variant keys — collapse version decorations for mapping
    if n.startswith("microsoft . net host fx resolver"):
        n = "microsoft .net host fx resolver - 6.0.36 x86"
    if n.startswith("microsoft . net host - 6.0.36"):
        n = "microsoft .net host - 6.0.36 x86"
    if n.startswith("microsoft . net runtime - 6.0.36"):
        n = "microsoft .net runtime - 6.0.36 x86"
    if n.startswith("microsoft windows desktop runtime - 6.0.36"):
        n = "microsoft windows desktop runtime - 6.0.36 x86"

    # Special token to recognize "Acrobat-x64-SDL"
    if "acrobat x64 sdl" in n:
        n = "acronym:acrobat-x64-sdl"

    return n

def guess_vendor_product(clean_name: str) -> Tuple[str, str]:
    """
    Fallback: derive vendor & product from the cleaned name.
    - Use VENDOR_HINTS to pick a vendor.
    - Product = cleaned name with vendor name removed, sanitized to underscores.
    """
    n = clean_name.lower()
    chosen_vendor = None
    for vendor, needles in VENDOR_HINTS:
        for word in needles:
            if word in n:
                chosen_vendor = vendor
                break
        if chosen_vendor:
            break
    if not chosen_vendor:
        # default to first word as vendor
        chosen_vendor = cpe_sanitize(n.split(" ")[0])

    # product: remove leading vendor word(s) if present
    product_text = n
    for v, needles in VENDOR_HINTS:
        for word in needles:
            if product_text.startswith(word + " "):
                product_text = product_text[len(word)+1:]
                break
    product = cpe_sanitize(product_text) or "product"

    return (cpe_sanitize(chosen_vendor), product)

def fix_component(comp: dict, verbose=False) -> dict:
    c = dict(comp)  # shallow copy

    original_name = c.get("name", "") or ""
    normalized = normalize_name(original_name)

    # version
    version = str(c.get("version", "") or "").strip()
    if not version:
        g = extract_version_from_name(normalized)
        if g:
            version = g
            c["version"] = version

    # clean base name (remove trailing version-ish token)
    clean_name = base_name_without_version(normalized) or normalized or original_name
    c["name"] = clean_name

    # properties: stash original name
    props = c.get("properties") or []
    props = [p for p in props if not (isinstance(p, dict) and p.get("name") == "original:name")]
    if original_name and original_name != clean_name:
        props.append({"name": "original:name", "value": original_name})
    c["properties"] = props

    # purl & bom-ref
    slug = slugify_name_for_purl(clean_name)
    new_purl = f"pkg:generic/{slug}" + (f"@{urllib.parse.quote(version, safe='.-_~')}" if version else "")
    c["purl"] = new_purl
    c["bom-ref"] = new_purl

    # choose CPE (known map first; otherwise synthesize)
    key = canonicalize_for_map(clean_name, version)
    vendor_product = KNOWN_CPE.get(key)
    if not vendor_product:
        vendor_product = KNOWN_CPE.get(clean_name.lower())

    if vendor_product:
        vendor, product = vendor_product
    else:
        vendor, product = guess_vendor_product(clean_name)

    vendor = cpe_sanitize(vendor)
    product = cpe_sanitize(product)
    ver = version or "0"

    cpe_val = build_cpe(vendor, product, ver)
    c["cpe"] = cpe_val
    # also reflect in properties for tools that read properties
    props = [p for p in c.get("properties", []) if p.get("name") != "cpe"]
    props.append({"name": "cpe", "value": cpe_val})
    c["properties"] = props

    if verbose:
        print(f"[FIX] name='{original_name}' -> '{clean_name}'  ver='{version}'  purl='{new_purl}'  cpe='{cpe_val}'")

    return c

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(description="Normalize a Windows SBOM & add CPEs for all components.")
    ap.add_argument("input", help="Path to CycloneDX JSON SBOM")
    ap.add_argument("-o", "--out", help="Output file (default: <input>.fixed.json)")
    ap.add_argument("--in-place", action="store_true", help="Overwrite input file")
    ap.add_argument("--verbose", action="store_true", help="Print per-component changes")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"ERROR: input not found: {in_path}", file=sys.stderr)
        sys.exit(2)

    try:
        sbom = json.loads(in_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(2)

    comps = sbom.get("components")
    if not isinstance(comps, list):
        print("ERROR: SBOM has no 'components' array.", file=sys.stderr)
        sys.exit(2)

    fixed = []
    for comp in comps:
        fixed.append(fix_component(comp, verbose=args.verbose))
    sbom["components"] = fixed

    # Keep headers sane
    sbom["bomFormat"] = sbom.get("bomFormat", "CycloneDX")
    sbom["specVersion"] = sbom.get("specVersion", "1.6")

    # Give the OS metadata a stable bom-ref
    meta = sbom.get("metadata") or {}
    host = meta.get("component")
    if isinstance(host, dict):
        osn = host.get("name", "windows")
        osv = str(host.get("version", "") or "")
        os_slug = slugify_name_for_purl(osn) or "os"
        host["bom-ref"] = f"pkg:generic/{os_slug}-os" + (f"@{urllib.parse.quote(osv, safe='.-_~')}" if osv else "")

    out_path = in_path if args.in_place else Path(args.out) if args.out else in_path.with_suffix(in_path.suffix + ".fixed.json")
    out_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"Wrote: {out_path}")
    print(f"Components processed: {len(fixed)} (CPEs added for ALL components)")

if __name__ == "__main__":
    main()
