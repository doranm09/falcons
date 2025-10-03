#!/usr/bin/env python3
"""
OpenVAS/GVM IP and Port Extractor

This script connects to the Greenbone Vulnerability Manager PostgreSQL database
and extracts IP addresses with their associated ports from scan results.
"""

import psycopg2
import json
import sys
from collections import defaultdict

def connect_to_gvm_db():
    """Connect to the GVM PostgreSQL database"""
    try:
        # Connect using the gvmd user (no password required for local container access)
        conn = psycopg2.connect(
            host="localhost",
            port="5432",
            database="gvmd",
            user="gvmd",
            # For container access, we'll use a direct connection approach
        )
        return conn
    except psycopg2.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def extract_ips_ports_docker():
    """Extract IP addresses and ports using docker exec"""
    try:
        import subprocess

        # Query to get IP addresses and their associated ports
        query = """
        SELECT DISTINCT
            host,
            port,
            COUNT(*) as finding_count,
            MAX(severity) as max_severity,
            string_agg(DISTINCT description, ' | ') as descriptions
        FROM results
        WHERE host IS NOT NULL AND port IS NOT NULL
        GROUP BY host, port
        ORDER BY host, port;
        """

        # Execute the query via docker exec
        cmd = [
            "docker", "exec", "greenbone-community-edition-pg-gvm-1",
            "psql", "-U", "gvmd", "-d", "gvmd", "-t", "-c", query
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing docker command: {e}")
        return None
    except FileNotFoundError:
        print("Docker command not found. Please ensure Docker is installed.")
        return None

def parse_and_format_results(raw_output):
    """Parse the raw PostgreSQL output and format it nicely"""
    if not raw_output:
        return None

    lines = raw_output.split('\n')
    ip_port_data = []

    for line in lines:
        if not line.strip():
            continue

        # PostgreSQL tabular output format: host | port | finding_count | max_severity
        # Split by '|' and handle extra spaces
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 4:
            host = parts[0]
            port = parts[1]
            finding_count = parts[2]
            max_severity = parts[3]

            # Skip if finding_count is empty
            if not finding_count or finding_count == '':
                continue

            ip_port_data.append({
                'ip_address': host,
                'port': port,
                'finding_count': int(finding_count),
                'max_severity': float(max_severity) if max_severity else 0.0,
                'descriptions': f"Vulnerability findings for {port}"
            })

    return ip_port_data

def display_results(data, format_type='table'):
    """Display results in the specified format"""
    if not data:
        print("No data found or error occurred.")
        return

    if format_type == 'json':
        print(json.dumps(data, indent=2))
    elif format_type == 'csv':
        print("IP Address,Port,Finding Count,Max Severity,Descriptions")
        for item in data:
            print(f"{item['ip_address']},{item['port']},{item['finding_count']},{item['max_severity']},{item['descriptions'].replace(',', ';')}")
    else:  # table format
        print(f"{'IP Address':<15} {'Port':<8} {'Findings':<10} {'Severity':<10} {'Description'}")
        print("-" * 80)
        for item in data:
            severity_str = f"{item['max_severity']:.1f}"
            print(f"{item['ip_address']:<15} {item['port']:<8} {item['finding_count']:<10} {severity_str:<10} {item['descriptions']}")

def main():
    """Main function"""
    print("OpenVAS/GVM IP and Port Extractor")
    print("=" * 40)

    # Extract data using docker exec approach
    print("Connecting to GVM database...")
    raw_data = extract_ips_ports_docker()

    if not raw_data:
        print("Failed to extract data from database.")
        sys.exit(1)

    # Parse and format the results
    print("Processing results...")
    formatted_data = parse_and_format_results(raw_data)

    if not formatted_data:
        print("No IP/port data found in scan results.")
        sys.exit(1)

    # Display results in table format by default
    print(f"\nFound {len(formatted_data)} IP/port combinations with scan findings:")
    display_results(formatted_data, 'table')

    # Also save to JSON file for programmatic use
    with open('openvas_ip_port_results.json', 'w') as f:
        json.dump(formatted_data, f, indent=2)

    print("\nResults also saved to 'openvas_ip_port_results.json'")

    # Show summary statistics
    total_findings = sum(item['finding_count'] for item in formatted_data)
    unique_ips = len(set(item['ip_address'] for item in formatted_data))
    high_severity = len([item for item in formatted_data if item['max_severity'] >= 7.0])

    print("\nSummary:")
    print(f"  Total IP addresses: {unique_ips}")
    print(f"  Total findings: {total_findings}")
    print(f"  High severity findings (7.0+): {high_severity}")

if __name__ == "__main__":
    main()
