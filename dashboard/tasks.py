# dashboard/tasks.py
from celery import shared_task
from .models import Node, Link
import subprocess
import ipaddress
import requests
from datetime import datetime
from .models import Vulnerability
from django.utils.dateparse import parse_datetime

@shared_task
def scan_network_task(cidr):
    from .models import ScanRun, Node, Link  # ensure local import in tasks
    import subprocess, ipaddress

    scan = ScanRun.objects.create(cidr=cidr, status="STARTED")

    network = ipaddress.ip_network(cidr, strict=False)
    found_nodes = []

    for ip in network.hosts():
        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            latency = parse_ping_latency(result.stdout)
            node = Node.objects.create(
                scan_run=scan,
                ip_address=str(ip),
                name=str(ip)
            )
            found_nodes.append((node, latency))

    # Create weighted links between nodes
    for i in range(len(found_nodes)):
        for j in range(i + 1, len(found_nodes)):
            node1, latency1 = found_nodes[i]
            node2, latency2 = found_nodes[j]
            avg_latency = (latency1 + latency2) / 2
            Link.objects.create(scan_run=scan, source=node1, destination=node2, weight=avg_latency)
            Link.objects.create(scan_run=scan, source=node2, destination=node1, weight=avg_latency)

    scan.status = "COMPLETE"
    scan.result_summary = f"{len(found_nodes)} nodes, {len(found_nodes)*(len(found_nodes)-1)} links"
    scan.save()

    return scan.result_summary

def parse_ping_latency(output):
    for line in output.decode().splitlines():
        if 'time=' in line:
            try:
                return float(line.split('time=')[-1].split()[0])
            except:
                pass
    return 100.0  # Fallback default

NVD_API_KEY = 'fd4ab0bd-f3a2-4ad2-bc30-c28a09163034'  # put in env later
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

def fetch_and_store_cves(keyword="scada"):
    headers = {'apiKey': NVD_API_KEY}
    params = {
        "keywordSearch": keyword,
        "startIndex": 0,
        "resultsPerPage": 100,
    }

    resp = requests.get(NVD_API_URL, headers=headers, params=params)
    data = resp.json()

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        published = parse_datetime(cve["published"])
        modified = parse_datetime(cve["lastModified"])
        score = None
        severity = ""

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]

        refs = "\n".join([
            r["url"]
            for r in cve.get("references", [])
            if "url" in r
        ])

        vuln, _ = Vulnerability.objects.update_or_create(
            cve_id=cve_id,
            defaults={
                "description": description,
                "published": published,
                "last_modified": modified,
                "score": score,
                "severity": severity,
                "references": refs
            }
        )