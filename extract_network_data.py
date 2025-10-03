#!/usr/bin/env python3
"""
Script to extract nodes, IP addresses, and open ports from the cyber_pen_test database.
This script queries the Django models to get network information from both the Node model
and AgentStatus model, which contain the relevant data.
"""

import os
import sys
import django
import json
from collections import defaultdict

# Add the project root to Python path
sys.path.append('/home/ifanlabadmin/git/cyber_pen_test')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_pen_test.settings')

# Setup Django
django.setup()

from dashboard.models import Node, AgentStatus, NetworkMetadata, NetworkConnection

def extract_node_data():
    """Extract data from Node model."""
    print("=== NODE MODEL DATA ===")

    nodes = Node.objects.all()
    node_data = []

    for node in nodes:
        node_info = {
            'id': node.id,
            'name': node.name,
            'ip_address': node.ip_address,
            'status': node.status,
            'agent_id': node.agent_id,
            'os_info': node.os_info,
            'mac_addresses': node.mac_addresses or [],
            'active_ports': node.active_ports or [],
            'last_heartbeat': node.last_heartbeat.isoformat() if node.last_heartbeat else None,
            'description': node.description
        }
        node_data.append(node_info)

        print(f"Node: {node.name}")
        print(f"  IP: {node.ip_address}")
        print(f"  Status: {node.status}")
        print(f"  Agent ID: {node.agent_id}")
        print(f"  OS: {node.os_info or 'Unknown'}")

        if node.active_ports:
            print(f"  Active Ports: {len(node.active_ports)} ports")
            for port in node.active_ports[:10]:  # Show first 10 ports
                print(f"    - Port {port}")
            if len(node.active_ports) > 10:
                print(f"    ... and {len(node.active_ports) - 10} more ports")
        else:
            print("  Active Ports: None found")

        if node.mac_addresses:
            print(f"  MAC Addresses: {node.mac_addresses}")

        print(f"  Last Heartbeat: {node.last_heartbeat}")
        print()

    return node_data

def extract_agent_data():
    """Extract data from AgentStatus model."""
    print("=== AGENT STATUS MODEL DATA ===")

    agents = AgentStatus.objects.all()
    agent_data = []

    for agent in agents:
        agent_info = {
            'agent_id': agent.agent_id,
            'hostname': agent.hostname,
            'ip_address': agent.ip_address,
            'status': agent.status,
            'os_type': agent.os_type,
            'os_version': agent.os_version,
            'platform': agent.platform,
            'active_ports': agent.active_ports or [],
            'interfaces': agent.interfaces or [],
            'last_heartbeat': agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
            'agent_version': agent.agent_version
        }
        agent_data.append(agent_info)

        print(f"Agent: {agent.hostname}")
        print(f"  Agent ID: {agent.agent_id}")
        print(f"  IP: {agent.ip_address}")
        print(f"  Status: {agent.status}")
        print(f"  OS: {agent.os_type} {agent.os_version}")
        print(f"  Platform: {agent.platform}")

        if agent.active_ports:
            print(f"  Active Ports: {len(agent.active_ports)} ports")
            for port in agent.active_ports[:10]:  # Show first 10 ports
                print(f"    - Port {port}")
            if len(agent.active_ports) > 10:
                print(f"    ... and {len(agent.active_ports) - 10} more ports")
        else:
            print("  Active Ports: None found")

        if agent.interfaces:
            print(f"  Interfaces: {len(agent.interfaces)} interfaces")
            for iface in agent.interfaces[:5]:  # Show first 5 interfaces
                print(f"    - {iface}")
            if len(agent.interfaces) > 5:
                print(f"    ... and {len(agent.interfaces) - 5} more interfaces")

        print(f"  Last Heartbeat: {agent.last_heartbeat}")
        print(f"  Version: {agent.agent_version}")
        print()

    return agent_data

def extract_network_metadata():
    """Extract data from NetworkMetadata model."""
    print("=== NETWORK METADATA ===")

    metadata_entries = NetworkMetadata.objects.all().order_by('-timestamp')[:10]  # Last 10 entries

    for metadata in metadata_entries:
        print(f"Metadata for {metadata.agent.hostname} at {metadata.timestamp}")
        print(f"  Collection Duration: {metadata.collection_duration_ms}ms")
        print(f"  Total Connections: {metadata.total_connections}")
        print(f"  Total Interfaces: {metadata.total_interfaces}")

        if metadata.active_ports:
            print(f"  Active Ports: {len(metadata.active_ports)} ports")
        if metadata.interfaces:
            print(f"  Interfaces: {len(metadata.interfaces)} interfaces")
        print()

def extract_open_ports_summary():
    """Create a summary of all open ports found."""
    print("=== OPEN PORTS SUMMARY ===")

    # Get all unique ports from Node model
    node_ports = set()
    nodes_with_ports = Node.objects.exclude(active_ports__isnull=True).exclude(active_ports__exact=[])

    for node in nodes_with_ports:
        if node.active_ports:
            for port in node.active_ports:
                node_ports.add((str(node.ip_address), port))

    # Get all unique ports from AgentStatus model
    agent_ports = set()
    agents_with_ports = AgentStatus.objects.exclude(active_ports__isnull=True).exclude(active_ports__exact=[])

    for agent in agents_with_ports:
        if agent.active_ports:
            for port in agent.active_ports:
                agent_ports.add((str(agent.ip_address), port))

    # Combine and organize by IP
    all_ports_by_ip = defaultdict(set)

    for ip, port in node_ports:
        all_ports_by_ip[ip].add(port)
    for ip, port in agent_ports:
        all_ports_by_ip[ip].add(port)

    # Display summary
    print(f"Total unique IP addresses with ports: {len(all_ports_by_ip)}")
    print()

    for ip in sorted(all_ports_by_ip.keys()):
        ports = sorted(all_ports_by_ip[ip])
        print(f"IP: {ip}")
        print(f"  Open Ports ({len(ports)}): {ports[:10]}")  # Show first 10 ports
        if len(ports) > 10:
            print(f"  ... and {len(ports) - 10} more ports")
        print()

    return dict(all_ports_by_ip)

def save_to_json(data, filename):
    """Save data to JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Data saved to {filename}")

def main():
    """Main function to extract all network data."""
    print("EXTRACTING NETWORK DATA FROM CYBER_PEN_TEST DATABASE")
    print("=" * 60)
    print()

    # Extract data from different models
    node_data = extract_node_data()
    agent_data = extract_agent_data()
    extract_network_metadata()
    ports_summary = extract_open_ports_summary()

    # Save detailed data to JSON files
    save_to_json(node_data, 'node_data.json')
    save_to_json(agent_data, 'agent_data.json')
    save_to_json(ports_summary, 'ports_summary.json')

    print("EXTRACTION COMPLETE")
    print("=" * 60)
    print(f"Node records: {len(node_data)}")
    print(f"Agent records: {len(agent_data)}")
    print(f"IP addresses with ports: {len(ports_summary)}")

    # Show sample of most active IPs
    if ports_summary:
        most_active = sorted(ports_summary.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        print("\nMost active IP addresses (by port count):")
        for ip, ports in most_active:
            print(f"  {ip}: {len(ports)} ports")

if __name__ == "__main__":
    main()
