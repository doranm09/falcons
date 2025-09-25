#!/usr/bin/env python3
"""
Convert Grype `-o json` output into the cyber.json schema.

- Reads from stdin by default (or --in file).
- Uses Grype JSON: .matches[].artifact + .matches[].vulnerability
- Populates vulnerabilities with rich fields:
    id, description, link, name, installed, fixed_in, type, severity, epss, risk, _match
- Deduplicates by (vuln.id, artifact.name, artifact.version).

Examples:
  grype -o json sbom:/path/to/sbom.json \
    | python grype_json_to_cyberjson.py \
        --system "gpwr" --node-id C1 --node-name "Valve Controller" \
        --desc "Feed Water Valve Controller" --type PLC --os "Ubuntu 22.04" \
        --out test.cyber.json

  # Or read from a saved grype.json
  python grype_json_to_cyberjson.py --in grype.json --system gpwr --node-id C1 --node-name "Valve Controller"
"""

import sys, json, argparse, re
from typing import Any, Dict, List, Tuple

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

def read_json(stdin_fallback: bool, in_path: str = "") -> Any:
    if in_path:
        with open(in_path, "r", encoding="utf-8") as f:
            txt = f.read()
    else:
        txt = sys.stdin.read()
    txt = txt.strip()
    if not txt:
        raise SystemExit("No JSON input provided. Pipe `grype -o json ...` or use --in file.")
    try:
        return json.loads(txt)
    except json.JSONDecodeError as e:
        # Some tools emit JSONL; try per-line parse into a list
        items = []
        for i, line in enumerate(txt.splitlines()):
            s = line.strip()
            if not s:
                continue
            try:
                items.append(json.loads(s))
            except json.JSONDecodeError:
                raise SystemExit(f"Invalid JSON at line {i+1}: {s[:200]} ...") from e
        return items

def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def safe_get(d: Any, *path, default=""):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur if cur is not None else default

def join_fix_versions(fix_obj: Dict[str, Any]) -> str:
    if not isinstance(fix_obj, dict):
        return ""
    versions = fix_obj.get("versions") or []
    return ", ".join(v for v in versions if isinstance(v, str))

def extract_epss(vul: Dict[str, Any]) -> str:
    # Try common places grype/advisory data may surface EPSS; otherwise blank
    return (
        str(safe_get(vul, "epss", default=""))
        or str(safe_get(vul, "metadata", "epss", default=""))
        or str(safe_get(vul, "dataSource", "epss", default=""))
    )

def extract_risk(vul: Dict[str, Any]) -> str:
    return (
        str(safe_get(vul, "riskScore", default=""))
        or str(safe_get(vul, "metadata", "riskScore", default=""))
    )

def best_artifact_type(art: Dict[str, Any]) -> str:
    for k in ("type", "language", "metadataType", "pkgType"):
        v = art.get(k)
        if isinstance(v, str) and v:
            return v
    return ""

def build_vuln(match: Dict[str, Any]) -> Dict[str, Any]:
    art = match.get("artifact") or {}
    vul = match.get("vulnerability") or {}

    vid = safe_get(vul, "id", default="")
    name = safe_get(art, "name", default="")
    installed = safe_get(art, "version", default="")
    fixed_in = join_fix_versions(vul.get("fix") or {})
    vtype = best_artifact_type(art)
    severity = safe_get(vul, "severity", default="")

    link = ""
    if CVE_RE.match(vid):
        link = f"https://www.cve.org/CVERecord?id={vid}"
    # else: leave blank; caller can post-process other ecosystems

    epss = extract_epss(vul)
    risk = extract_risk(vul)

    # Keep a light-weight copy of the match for traceability (ids + a few key fields)
    keep = {
        "matchDetails": safe_get(match, "matchDetails", default=[]),
        "relatedVulnerabilities": safe_get(match, "relatedVulnerabilities", default=[]),
        "artifact": {k: art.get(k) for k in ("name","version","type","language","metadataType") if k in art},
        "vulnerability": {k: vul.get(k) for k in ("id","severity","namespace","dataSource","fix") if k in vul},
    }

    return {
        "id": vid,
        "description": "",  # optional free-text if you want to add later
        "link": link,
        "name": name,
        "installed": installed,
        "fixed_in": fixed_in,
        "type": vtype,
        "severity": severity,
        "epss": epss,
        "risk": risk,
        "_match": keep,
    }

def dedupe(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[Tuple[str,str,str]] = set()
    out: List[Dict[str, Any]] = []
    for v in vulns:
        key = (v.get("id",""), v.get("name",""), v.get("installed",""))
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out

def parse_grype_matches(doc: Any) -> List[Dict[str, Any]]:
    # Grype normally emits a dict with "matches"
    docs = []
    if isinstance(doc, dict):
        docs = [doc]
    elif isinstance(doc, list):
        docs = doc
    else:
        return []

    vulns: List[Dict[str, Any]] = []
    for d in docs:
        for m in as_list(d.get("matches") or []):
            # Only include if there's an ID and it looks like a vuln
            v = build_vuln(m)
            if v.get("id"):
                vulns.append(v)
    return dedupe(vulns)

def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert Grype -o json to cyber.json schema")
    ap.add_argument("--system", required=True, help="Top-level system name")
    ap.add_argument("--node-id", required=True)
    ap.add_argument("--node-name", required=True)
    ap.add_argument("--desc", default="")
    ap.add_argument("--type", default="PLC")
    ap.add_argument("--os", dest="os_", default="")
    ap.add_argument("--mac", action="append", default=[])
    ap.add_argument("--port", action="append", default=[],
                    help="Port as ip:port/PROTO (repeatable)")
    ap.add_argument("--lib", action="append", default=[])
    ap.add_argument("--comm", action="append", default=[],
                    help="local=ip:port remote=ip:port protocol=TCP period=Yes volume=200 state=Active id=nX")
    ap.add_argument("--det", action="append", default=[],
                    help="detector=<id> attack_type=<t> src=<ip> dst=<ip> start=YYYY-mm-dd HH:MM:SS end=YYYY-mm-dd HH:MM:SS conf=0.9")
    ap.add_argument("--out", help="Output file (default: stdout)")
    ap.add_argument("--in", dest="infile", help="Read Grype JSON from file instead of stdin")
    args = ap.parse_args(argv)

    doc = read_json(stdin_fallback=not bool(args.infile), in_path=args.infile or "")
    vulns = parse_grype_matches(doc)

    # Ports
    import re as _re
    ports = []
    for pdef in args.port:
        m = _re.match(r"^(?P<ip>[^:/\s]+):(?P<port>\d+)(?:/(?P<proto>\w+))?$", pdef.strip())
        if not m:
            continue
        proto = (m.group("proto") or "TCP").upper()
        ports.append({"id": f"{m.group('ip')}:{m.group('port')}", "Protocol": proto})

    # Communication
    comm = []
    for c in args.comm:
        kvs = dict(kv.split("=",1) for kv in c.split() if "=" in kv)
        comm.append({
            "id": kvs.get("id", f"n{len(comm)+1}"),
            "local": kvs.get("local",""),
            "remote": kvs.get("remote",""),
            "protocol": kvs.get("protocol","TCP"),
            "period": kvs.get("period","Yes"),
            "volume": kvs.get("volume",""),
            "state": kvs.get("state","Active"),
        })

    # Detection
    det = []
    for dct in args.det:
        kvs = dict(kv.split("=",1) for kv in dct.split() if "=" in kv)
        det.append({
            "detector": kvs.get("detector", args.node_id),
            "id": kvs.get("id", f"d{len(det)+1}"),
            "attack_type": kvs.get("attack_type",""),
            "attack_source": kvs.get("src",""),
            "attack_target": kvs.get("dst",""),
            "start_time": kvs.get("start",""),
            "end_time": kvs.get("end",""),
            "confidence": kvs.get("conf",""),
        })

    out_obj = {
        "version": "0.1",
        "system": args.system,
        "scanned_nodes": [{
            "id": args.node_id,
            "name": args.node_name,
            "description": args.desc,
            "type": args.type,
            "OS": args.os_,
            "lib": args.lib,
            "MAC": args.mac,
            "port": ports,
            "vulnerability": vulns,
            "reachability": []
        }],
        "communication": comm,
        "detection": det,
    }

    txt = json.dumps(out_obj, indent=4)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(txt)
    else:
        sys.stdout.write(txt)

if __name__ == "__main__":
    main()
