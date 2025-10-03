import json
import os
import re
from typing import Any, Dict, List

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

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

    epss = extract_epss(vul)
    risk = extract_risk(vul)

    keep = {
        "matchDetails": safe_get(match, "matchDetails", default=[]),
        "relatedVulnerabilities": safe_get(match, "relatedVulnerabilities", default=[]),
        "artifact": {k: art.get(k) for k in ("name","version","type","language","metadataType") if k in art},
        "vulnerability": {k: vul.get(k) for k in ("id","severity","namespace","dataSource","fix") if k in vul},
    }

    return {
        "id": vid,
        "description": "",
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
    seen: set[tuple[str,str,str]] = set()
    out: List[Dict[str, Any]] = []
    for v in vulns:
        key = (v.get("id",""), v.get("name",""), v.get("installed",""))
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out

def parse_grype_matches(doc: Any) -> List[Dict[str, Any]]:
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
            v = build_vuln(m)
            if v.get("id"):
                vulns.append(v)
    return dedupe(vulns)

def main():
    # Read the OpenVAS results
    with open('openvas_ip_port_results.json', 'r') as f:
        openvas_data = json.load(f)

    # Read and parse Grype data
    grype_file = 'utils/grype_to_json/grype_output/grype_gpwr.json'
    grype_vulns = []
    if os.path.exists(grype_file):
        with open(grype_file, 'r') as f:
            grype_doc = json.load(f)
        grype_vulns = parse_grype_matches(grype_doc)

    # Group by IP
    nodes = {}
    for entry in openvas_data:
        ip = entry['ip_address']
        port = entry['port']
        max_severity = entry['max_severity']

        if ip not in nodes:
            nodes[ip] = {'ports': [], 'vulnerabilities': []}

        # Add ports if it's a specific port/tcp or udp
        if '/' in port:
            port_num, proto = port.split('/', 1)
            if port_num.isdigit():
                nodes[ip]['ports'].append({"id": f"{ip}:{port_num}", "Protocol": proto.upper()})

        # Add vulnerability if severity > 0
        if max_severity > 0:
            vuln_id = f"OV-{port.replace('/', '-')}-{max_severity}"
            vuln_name = port
            vuln = {
                "id": vuln_id,
                "description": "",
                "link": "",
                "name": vuln_name,
                "installed": "",
                "fixed_in": "",
                "type": "",
                "severity": str(max_severity),
                "epss": "",
                "risk": ""
            }
            nodes[ip]['vulnerabilities'].append(vuln)

    # Create scanned_nodes
    scanned_nodes = []
    ips = list(nodes.keys())
    for i, ip in enumerate(ips):
        node = {
            "id": f"N{i+1}",
            "name": f"Node at {ip}",
            "description": "Scanned node from OpenVAS",
            "type": "Server",
            "OS": "Unknown",
            "lib": [],
            "MAC": [],
            "port": nodes[ip]['ports'],
            "vulnerability": nodes[ip]['vulnerabilities'] + grype_vulns,
            "reachability": []
        }

        # Add reachability: connect to other IPs
        for other_ip in ips:
            if other_ip != ip:
                node['reachability'].append({
                    "target": other_ip,
                    "source": ip,
                    "type": "ethernet",
                    "direction": "both"
                })

        scanned_nodes.append(node)

    # Create communication - add a sample one
    communication = []
    if len(ips) >= 2:
        comm = {
            "id": "n1",
            "local": f"{ips[0]}:{nodes[ips[0]]['ports'][0]['id'].split(':')[1] if nodes[ips[0]]['ports'] else '80'}",
            "remote": f"{ips[1]}:{nodes[ips[1]]['ports'][0]['id'].split(':')[1] if nodes[ips[1]]['ports'] else '80'}",
            "protocol": "TCP",
            "period": "Unknown",
            "volume": "0",
            "state": "Unknown"
        }
        communication.append(comm)

    # Detection - empty
    detection = []

    # Create the populated template
    populated = {
        "version": "0.1",
        "system": "Cyber Pen Test System",
        "scanned_nodes": scanned_nodes,
        "communication": communication,
        "detection": detection
    }

    # Write to file
    with open('populated_cyber_template.json', 'w') as f:
        json.dump(populated, f, indent=2)

if __name__ == "__main__":
    main()
