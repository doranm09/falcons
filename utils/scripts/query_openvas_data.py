#!/usr/bin/env python3
"""
Script to query OpenVAS scan data from the cyber_pen_test database.
This script queries the Django models to get OpenVAS scan results, vulnerabilities,
and associated network information.
"""

import os
import sys
import django
import json
from datetime import datetime, timedelta
from collections import defaultdict

# Add the project root to Python path
sys.path.append('/home/ifanlabadmin/git/cyber_pen_test')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_pen_test.settings')

# Setup Django
django.setup()

from dashboard.models import ScanRun, Vulnerability, ScanVulnerability, Node

def query_openvas_scans():
    """Query all OpenVAS scan runs."""
    print("=== OPENVAS SCAN RUNS ===")

    # Get all OpenVAS scan runs
    openvas_scans = ScanRun.objects.filter(scan_type="openvas").order_by('-timestamp')

    scan_data = []

    for scan in openvas_scans:
        scan_info = {
            'id': scan.id,
            'timestamp': scan.timestamp.isoformat() if scan.timestamp else None,
            'cidr': scan.cidr,
            'status': scan.status,
            'result_summary': scan.result_summary,
            'openvas_task_id': scan.openvas_task_id,
            'scan_type': scan.scan_type,
            'vulnerabilities_count': scan.vulnerabilities.count(),
            'nodes_count': scan.nodes.count()
        }
        scan_data.append(scan_info)

        print(f"Scan ID: {scan.id}")
        print(f"  Timestamp: {scan.timestamp}")
        print(f"  CIDR: {scan.cidr}")
        print(f"  Status: {scan.status}")
        print(f"  OpenVAS Task ID: {scan.openvas_task_id}")
        print(f"  Summary: {scan.result_summary or 'None'}")
        print(f"  Vulnerabilities: {scan.vulnerabilities.count()}")
        print(f"  Nodes Discovered: {scan.nodes.count()}")
        print()

    return scan_data

def query_openvas_vulnerabilities():
    """Query all vulnerabilities from OpenVAS scans."""
    print("=== OPENVAS VULNERABILITIES ===")

    # Get all scan vulnerabilities (per-scan findings)
    scan_vulns = ScanVulnerability.objects.all().order_by('-timestamp')

    vuln_data = []

    for vuln in scan_vulns:
        vuln_info = {
            'id': vuln.id,
            'scan_run_id': vuln.scan_run_id,
            'host_ip': vuln.host_ip,
            'cve_id': vuln.cve_id,
            'name': vuln.name,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'description': vuln.description,
            'timestamp': vuln.timestamp.isoformat() if vuln.timestamp else None
        }
        vuln_data.append(vuln_info)

        print(f"Vulnerability: {vuln.cve_id}")
        print(f"  Host IP: {vuln.host_ip}")
        print(f"  Name: {vuln.name}")
        print(f"  Severity: {vuln.severity}")
        print(f"  CVSS Score: {vuln.cvss_score}")
        print(f"  Description: {vuln.description or 'None'}")
        print(f"  Scan Run ID: {vuln.scan_run_id}")
        print(f"  Timestamp: {vuln.timestamp}")
        print()

    return vuln_data

def query_global_vulnerabilities():
    """Query global vulnerability catalog."""
    print("=== GLOBAL VULNERABILITY CATALOG ===")

    # Get all global vulnerabilities
    global_vulns = Vulnerability.objects.all().order_by('-last_modified')

    vuln_data = []

    for vuln in global_vulns:
        vuln_info = {
            'id': vuln.id,
            'cve_id': vuln.cve_id,
            'description': vuln.description,
            'severity': vuln.severity,
            'score': vuln.score,
            'published': vuln.published.isoformat() if vuln.published else None,
            'last_modified': vuln.last_modified.isoformat() if vuln.last_modified else None,
            'references': vuln.references,
            'nodes_count': vuln.nodes.count()
        }
        vuln_data.append(vuln_info)

        print(f"CVE: {vuln.cve_id}")
        print(f"  Description: {vuln.description[:100]}..." if len(vuln.description) > 100 else f"  Description: {vuln.description}")
        print(f"  Severity: {vuln.severity}")
        print(f"  CVSS Score: {vuln.score}")
        print(f"  Published: {vuln.published}")
        print(f"  Last Modified: {vuln.last_modified}")
        print(f"  Affected Nodes: {vuln.nodes.count()}")
        print(f"  References: {vuln.references[:100]}..." if vuln.references and len(vuln.references) > 100 else f"  References: {vuln.references or 'None'}")
        print()

    return vuln_data

def query_openvas_nodes():
    """Query nodes discovered by OpenVAS scans."""
    print("=== NODES FROM OPENVAS SCANS ===")

    # Get nodes that were part of OpenVAS scans
    openvas_nodes = Node.objects.filter(scan_run__scan_type="openvas").distinct()

    node_data = []

    for node in openvas_nodes:
        node_info = {
            'id': node.id,
            'name': node.name,
            'ip_address': node.ip_address,
            'status': node.status,
            'agent_id': node.agent_id,
            'scan_run_id': node.scan_run_id,
            'os_info': node.os_info,
            'active_ports': node.active_ports,
            'mac_addresses': node.mac_addresses,
            'last_heartbeat': node.last_heartbeat.isoformat() if node.last_heartbeat else None
        }
        node_data.append(node_info)

        print(f"Node: {node.name}")
        print(f"  IP: {node.ip_address}")
        print(f"  Status: {node.status}")
        print(f"  Agent ID: {node.agent_id}")
        print(f"  OS Info: {node.os_info or 'Unknown'}")
        print(f"  Scan Run ID: {node.scan_run_id}")

        if node.active_ports:
            print(f"  Active Ports: {len(node.active_ports)} ports")
            for port in node.active_ports[:5]:  # Show first 5 ports
                print(f"    - Port {port}")
            if len(node.active_ports) > 5:
                print(f"    ... and {len(node.active_ports) - 5} more ports")
        else:
            print("  Active Ports: None found")

        if node.mac_addresses:
            print(f"  MAC Addresses: {node.mac_addresses}")

        print()

    return node_data

def query_recent_openvas_activity():
    """Query recent OpenVAS activity (last 30 days)."""
    print("=== RECENT OPENVAS ACTIVITY (Last 30 Days) ===")

    thirty_days_ago = datetime.now() - timedelta(days=30)

    # Recent OpenVAS scans
    recent_scans = ScanRun.objects.filter(
        scan_type="openvas",
        timestamp__gte=thirty_days_ago
    ).order_by('-timestamp')

    print(f"Recent OpenVAS scans ({recent_scans.count()} found):")
    for scan in recent_scans:
        print(f"  - {scan.timestamp}: {scan.cidr} ({scan.status}) - {scan.vulnerabilities.count()} vulnerabilities")

    # Recent vulnerabilities
    recent_vulns = ScanVulnerability.objects.filter(
        timestamp__gte=thirty_days_ago
    ).order_by('-timestamp')

    print(f"\nRecent vulnerabilities ({recent_vulns.count()} found):")
    for vuln in recent_vulns[:10]:  # Show first 10
        print(f"  - {vuln.timestamp}: {vuln.cve_id} on {vuln.host_ip} ({vuln.severity})")

    return {
        'recent_scans_count': recent_scans.count(),
        'recent_vulns_count': recent_vulns.count()
    }

def query_vulnerability_summary():
    """Query vulnerability summary by severity."""
    print("=== VULNERABILITY SUMMARY ===")

    # Summary by severity for scan vulnerabilities
    severity_counts = ScanVulnerability.objects.values('severity').annotate(
        count=models.Count('severity')
    )

    print("Vulnerabilities by Severity:")
    total_vulns = 0
    for item in severity_counts:
        severity = item['severity'] or 'Unknown'
        count = item['count']
        total_vulns += count
        print(f"  {severity}: {count}")

    print(f"  Total: {total_vulns}")

    # Summary by host IP
    host_counts = ScanVulnerability.objects.values('host_ip').annotate(
        count=models.Count('host_ip')
    ).order_by('-count')

    print("
Top 10 Most Vulnerable Hosts:")
    for item in host_counts[:10]:
        print(f"  {item['host_ip']}: {item['count']} vulnerabilities")

    return {
        'total_vulnerabilities': total_vulns,
        'severity_breakdown': {item['severity']: item['count'] for item in severity_counts},
        'host_breakdown': {item['host_ip']: item['count'] for item in host_counts}
    }

def save_to_json(data, filename):
    """Save data to JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Data saved to {filename}")

def main():
    """Main function to query all OpenVAS data."""
    print("QUERYING OPENVAS DATA FROM CYBER_PEN_TEST DATABASE")
    print("=" * 60)
    print()

    # Query different types of OpenVAS data
    scan_data = query_openvas_scans()
    vuln_data = query_openvas_vulnerabilities()
    global_vuln_data = query_global_vulnerabilities()
    node_data = query_openvas_nodes()
    recent_activity = query_recent_openvas_activity()
    vuln_summary = query_vulnerability_summary()

    # Save detailed data to JSON files
    save_to_json(scan_data, 'openvas_scans.json')
    save_to_json(vuln_data, 'openvas_vulnerabilities.json')
    save_to_json(global_vuln_data, 'global_vulnerabilities.json')
    save_to_json(node_data, 'openvas_nodes.json')

    # Save summary data
    summary_data = {
        'recent_activity': recent_activity,
        'vulnerability_summary': vuln_summary,
        'collection_timestamp': datetime.now().isoformat()
    }
    save_to_json(summary_data, 'openvas_summary.json')

    print("OPENVAS DATA QUERY COMPLETE")
    print("=" * 60)
    print(f"OpenVAS Scan Runs: {len(scan_data)}")
    print(f"Scan Vulnerabilities: {len(vuln_data)}")
    print(f"Global Vulnerabilities: {len(global_vuln_data)}")
    print(f"Nodes from OpenVAS: {len(node_data)}")
    print(f"Recent Activity: {recent_activity['recent_scans_count']} scans, {recent_activity['recent_vulns_count']} vulnerabilities")

if __name__ == "__main__":
    main()
