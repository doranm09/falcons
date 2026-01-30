# dashboard/tasks.py
from celery import shared_task
from .models import Node, Link, ScanRun, Vulnerability
from .openvas_client import openvas_session, create_target, start_scan, get_report_id, download_report
from django.utils.timezone import now
import time
import xml.etree.ElementTree as ET
import subprocess
import ipaddress
import requests
import re
from datetime import datetime
from .models import Vulnerability
from django.utils.dateparse import parse_datetime

@shared_task
def scan_network_task(cidr):
    from .models import ScanRun, Node, Link  # ensure local import in tasks
    import subprocess, ipaddress

    scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type="ping")

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


@shared_task
def nmap_discovery_task(cidr):
    scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type="nmap")
    found_ips = []

    try:
        result = subprocess.run(
            ["nmap", "-sn", cidr, "-oG", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "nmap failed")

        for line in result.stdout.splitlines():
            if "Status: Up" not in line:
                continue
            match = re.search(r"Host:\\s+(\\S+)", line)
            if match:
                found_ips.append(match.group(1))

        for ip in found_ips:
            Node.objects.create(scan_run=scan, ip_address=ip, name=ip)

        scan.status = "COMPLETE"
        scan.result_summary = f"{len(found_ips)} hosts discovered (nmap)"
    except Exception as e:
        scan.status = "FAILED"
        scan.result_summary = str(e)

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

@shared_task
def launch_openvas_scan_task(cidr, config_name=None):
    scan = ScanRun.objects.create(cidr=cidr, status="IN_PROGRESS", scan_type="openvas")

    try:
        gmp = openvas_session()
        target_id = create_target(gmp, cidr)
        task_id = start_scan(gmp, target_id, config_name=config_name)
        scan.openvas_task_id = task_id
        scan.result_summary = f"OpenVAS scan launched. Task ID: {task_id}"
    except Exception as e:
        scan.status = "FAILED"
        scan.result_summary = str(e)

    scan.save()
    return scan.result_summary

@shared_task
def poll_openvas_results():
    scans = ScanRun.objects.filter(status="IN_PROGRESS", scan_type="openvas")

    for scan in scans:
        try:
            gmp = openvas_session()
            task = gmp.get_task(scan.openvas_task_id)
            status = task.xpath("//task/status/text()")[0]

            if status != "Done":
                continue

            report_id = get_report_id(gmp, scan.openvas_task_id)
            report_xml = download_report(gmp, report_id)
            parse_and_save_vulnerabilities(report_xml, scan)

            scan.status = "COMPLETE"
            scan.result_summary = f"Scan complete. Report ID: {report_id}"
            scan.save()

        except Exception as e:
            scan.result_summary = f"Polling error: {e}"
            scan.save()
