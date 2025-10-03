#!/usr/bin/env python3
"""
aggregate_cyber_template.py — Aggregate agent data to produce complete cyber template JSON.

This script aggregates data from multiple agents stored in the dashboard to create
the complete cyber_template.json structure including:
- Multiple scanned nodes with agent-collected data
- Vulnerability data from scans and SBOM analysis
- Reachability data based on network connections
- Communication data from observed network flows
- Detection data (placeholders for now, can be extended)

Usage:
    python manage.py aggregate_cyber_template
    OR
    python utils/aggregate_cyber_template.py --standalone
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to path for standalone execution
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

def setup_django():
    """Setup Django environment for standalone script execution."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_pen_test.settings')
    import django
    django.setup()

def best_artifact_type(art: Dict[str, Any]) -> str:
    """Determine the best artifact type from grype artifact data."""
    for k in ("type", "language", "metadataType", "pkgType"):
        v = art.get(k)
        if isinstance(v, str) and v:
            return v
    return ""

class CyberTemplateAggregator:
    """Aggregates agent data into complete cyber template JSON."""

    def __init__(self):
        self.system_name = "Control Water System"  # Can be configurable
        self.nodes = []
        self.communications = []
        self.detections = []

    def get_agents_data(self) -> List[Dict[str, Any]]:
        """Get all agent data from database."""
        from dashboard.models import Node, AgentStatus, Vulnerability

        agents_data = []

        # Get data from Node model (legacy)
        nodes = Node.objects.filter(agent_id__isnull=False).exclude(agent_id='')
        for node in nodes:
            cyber_data = node.get_cyber_template_data()

            # Try to enhance library data with SBOM
            enhanced_cyber_data = self.enhance_cyber_data_with_sbom(cyber_data, node.agent_id)

            node_data = {
                'agent_id': node.agent_id,
                'ip': str(node.ip_address),
                'name': node.name or f"Agent_{node.agent_id[:8]}",
                'description': node.description or f"Agent node {node.agent_id}",
                'type': getattr(node, 'device_type', 'PLC'),  # Default to PLC
                'cyber_data': enhanced_cyber_data,
                'vulnerabilities': self.get_node_vulnerabilities(node) + self.get_vulnerabilities_from_grype(node.agent_id),
                'interfaces': node.interfaces.all().values_list('ip', 'mac') if hasattr(node, 'interfaces') else []
            }
            agents_data.append(node_data)

        # Get data from AgentStatus model (current)
        agents = AgentStatus.objects.filter(status='online')
        for agent in agents:
            # Skip if we already have this agent from Node model
            if any(n['agent_id'] == agent.agent_id for n in agents_data):
                continue

            # Construct cyber data from AgentStatus
            cyber_data = {
                'OS': f"{agent.os_type} {agent.os_version}" if agent.os_type else "Unknown",
                'lib': [],  # AgentStatus doesn't store libraries, try SBOM
                'MAC': [],
                'port': agent.active_ports or []
            }

            # Get MAC from interfaces if available
            if agent.interfaces:
                for iface in agent.interfaces:
                    if iface.get('mac') and iface['mac'] != '00:00:00:00:00:00':
                        cyber_data['MAC'].append(iface['mac'])

            # Enhance with SBOM data
            enhanced_cyber_data = self.enhance_cyber_data_with_sbom(cyber_data, agent.agent_id)

            node_data = {
                'agent_id': agent.agent_id,
                'ip': str(agent.ip_address) if agent.ip_address else '',
                'name': agent.hostname or f"Agent_{agent.agent_id[:8]}",
                'description': f"Agent {agent.hostname} ({agent.agent_id})",
                'type': 'PLC',  # Default, could be detected from system info
                'cyber_data': enhanced_cyber_data,
                'vulnerabilities': self.get_vulnerabilities_from_grype(agent.agent_id),
                'interfaces': [(iface.get('ip'), iface.get('mac')) for iface in (agent.interfaces or [])]
            }
            agents_data.append(node_data)

        # Also add data from SBOM files directly if no agent data
        sbom_agents = self.get_agents_from_sbom_files()
        for sbom_agent in sbom_agents:
            if not any(n['agent_id'] == sbom_agent['agent_id'] for n in agents_data):
                agents_data.append(sbom_agent)

        return agents_data

    def get_node_vulnerabilities(self, node) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific node."""
        from dashboard.models import Vulnerability, ScanVulnerability

        vulnerabilities = []

        # Get vulnerabilities from many-to-many relationship
        for vuln in node.vulnerability_set.all():
            vuln_data = {
                'id': vuln.cve_id,
                'description': vuln.description,
                'link': f"https://www.cve.org/CVERecord?id={vuln.cve_id}",
                'severity': vuln.severity,
                'score': vuln.score
            }
            vulnerabilities.append(vuln_data)

        return vulnerabilities

    def enhance_cyber_data_with_sbom(self, cyber_data: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        """Enhance cyber data with SBOM library information."""
        enhanced_data = cyber_data.copy()

        # Look for SBOM files for this agent
        sbom_dir = Path("sbom_results")
        if sbom_dir.exists():
            possible_sbom_files = list(sbom_dir.glob("*.json"))
            for sbom_file in possible_sbom_files:
                try:
                    with open(sbom_file, 'r') as f:
                        sbom_data = json.load(f)

                    # Extract libraries from SBOM
                    libs = self.extract_libs_from_sbom(sbom_data)
                    if libs and not enhanced_data['lib']:  # Only add if we don't have agent-collected libs
                        enhanced_data['lib'] = libs[:100]  # Limit for template
                        break  # Use first valid SBOM

                except (json.JSONDecodeError, FileNotFoundError):
                    continue

        return enhanced_data

    def extract_libs_from_sbom(self, sbom_data: Dict[str, Any]) -> List[str]:
        """Extract library/package information from SBOM."""
        libs = []

        # Handle different SBOM formats
        if 'packages' in sbom_data:
            # Custom format
            for pkg in sbom_data['packages']:
                if isinstance(pkg, dict):
                    name = pkg.get('name', '')
                    version = pkg.get('version', '')
                    if name:
                        libs.append(f"{name}@{version}" if version else name)
                else:
                    libs.append(str(pkg))

        elif 'components' in sbom_data:
            # CycloneDX format
            for component in sbom_data['components']:
                name = component.get('name', '')
                version = component.get('version', '')
                if name:
                    libs.append(f"{name}@{version}" if version else name)

        return libs

    def get_vulnerabilities_from_grype(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities from grype JSON files for this agent."""
        vulnerabilities = []

        # Look for grype files in sbom_results
        grype_dir = Path("sbom_results")
        if grype_dir.exists():
            grype_files = list(grype_dir.glob("*grype*.json")) + list(grype_dir.glob("*grype*.txt"))

            for grype_file in grype_files:
                try:
                    if grype_file.suffix == '.json':
                        with open(grype_file, 'r') as f:
                            grype_data = json.load(f)

                        # Process matches from grype JSON
                        matches = grype_data.get('matches', [])
                        for match in matches[:20]:  # Limit per file
                            art = match.get('artifact', {})
                            vul = match.get('vulnerability', {})

                            vuln_data = {
                                'id': vul.get('id', ''),
                                'description': '',
                                'link': f"https://www.cve.org/CVERecord?id={vul.get('id', '')}" if vul.get('id', '').startswith('CVE-') else '',
                                'name': art.get('name', ''),
                                'installed': art.get('version', ''),
                                'severity': vul.get('severity', ''),
                                'type': best_artifact_type(art)
                            }
                            if vuln_data['id']:
                                vulnerabilities.append(vuln_data)

                    elif grype_file.suffix == '.txt':
                        # Parse grype text output (basic)
                        with open(grype_file, 'r') as f:
                            content = f.read()
                        # Simple parsing - look for CVE lines
                        lines = content.split('\n')
                        for line in lines[:20]:  # Limit
                            if 'CVE-' in line:
                                parts = line.split()
                                if parts:
                                    vuln_data = {
                                        'id': parts[0] if 'CVE-' in parts[0] else '',
                                        'description': '',
                                        'link': f"https://www.cve.org/CVERecord?id={parts[0]}" if 'CVE-' in parts[0] else '',
                                        'name': '',
                                        'installed': '',
                                        'severity': '',
                                        'type': ''
                                    }
                                    if vuln_data['id']:
                                        vulnerabilities.append(vuln_data)

                except (json.JSONDecodeError, FileNotFoundError, IndexError):
                    continue

        return vulnerabilities[:50]  # Overall limit

    def get_agents_from_sbom_files(self) -> List[Dict[str, Any]]:
        """Get agent data directly from SBOM files when no agent data in DB."""
        agents = []

        sbom_dir = Path("sbom_results")
        if not sbom_dir.exists():
            return agents

        # Process SBOM JSON files
        sbom_files = list(sbom_dir.glob("*.json"))
        excluded_files = ['gpwr.json', 'historian.json', 'pentest.json']  # Skip these as they're not pure SBOMs

        for sbom_file in sbom_files:
            if sbom_file.name in excluded_files:
                continue

            try:
                with open(sbom_file, 'r') as f:
                    sbom_data = json.load(f)

                # Generate agent_id from filename
                agent_id = sbom_file.stem.replace('_', '').replace('-', '')[:16]

                # Extract libraries
                libs = self.extract_libs_from_sbom(sbom_data)

                # Create agent data
                agent_data = {
                    'agent_id': agent_id,
                    'ip': '',  # Will be inferred from reachability
                    'name': f"SBOM_{sbom_file.stem[:12]}",
                    'description': f"Node from SBOM: {sbom_file.name}",
                    'type': 'Server',  # Default for SBOM-based nodes
                    'cyber_data': {
                        'OS': "Linux",  # Default, could be extracted from SBOM
                        'lib': libs[:100],
                        'MAC': [],  # No MAC from SBOM
                        'port': []  # No ports from SBOM
                    },
                    'vulnerabilities': self.get_vulnerabilities_from_grype(agent_id),
                    'interfaces': []  # No interfaces from SBOM
                }

                agents.append(agent_data)

            except (json.JSONDecodeError, FileNotFoundError):
                continue

        return agents

    def generate_reachability_data(self, agents_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate reachability data based on agent interfaces."""
        reachability = []

        # Simple reachability: assume agents can reach each other via their interfaces
        for i, agent1 in enumerate(agents_data):
            for j, agent2 in enumerate(agents_data):
                if i == j:
                    continue  # Skip self-reachability

                # Get IPs and MACs for both agents
                agent1_ips = [iface[0] for iface in agent1['interfaces'] if iface[0]]
                agent1_macs = [iface[1] for iface in agent1['interfaces'] if iface[1]]

                agent2_ips = [iface[0] for iface in agent2['interfaces'] if iface[0]]
                agent2_macs = [iface[1] for iface in agent2['interfaces'] if iface[1]]

                # Create reachability entry for each IP combination
                for ip1 in agent1_ips[:1]:  # Use first IP for simplicity
                    for ip2 in agent2_ips[:1]:
                        entry = {
                            'target': ip2,
                            'source': ip1,
                            'type': 'ethernet',
                            'direction': 'both'
                        }
                        reachability.append(entry)

                    # MAC-based reachability
                    for mac2 in agent2_macs[:1]:
                        mac2_clean = mac2.replace(':', '-').upper() if mac2 else ''
                        if mac2_clean:
                            entry = {
                                'target': mac2_clean,
                                'source': '-'.join(agent1_macs[0].split(':')).upper() if agent1_macs else '00-00-00-00-00-00',
                                'type': 'ethernet',
                                'direction': 'both'
                            }
                            reachability.append(entry)

        return reachability[:20]  # Limit for template size

    def generate_communication_data(self, agents_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate communication data based on agent connections."""
        communications = []

        from dashboard.models import NetworkConnection, NetworkFlow

        # Get all network connections from the database
        connections = NetworkConnection.objects.all().order_by('-last_seen')[:50]  # Limit to recent

        for i, conn in enumerate(connections):
            comm_data = {
                'id': f'n{i+1}',
                'local': conn.local_address or '',
                'remote': conn.remote_address or '',
                'protocol': conn.protocol,
                'period': 'Yes',  # Assume periodic
                'volume': '200',  # Default volume, could calculate from flows
                'state': conn.status or 'Active'
            }
            communications.append(comm_data)

        # If no connections in DB, create sample communications based on agent IPs
        if not communications:
            for i, agent1 in enumerate(agents_data):
                for j, agent2 in enumerate(agents_data):
                    if i >= j:  # Avoid duplicates
                        continue

                    agent1_ip = agent1.get('ip', '').split('/')[0] if '/' in agent1.get('ip', '') else agent1.get('ip', '')
                    agent2_ip = agent2.get('ip', '').split('/')[0] if '/' in agent2.get('ip', '') else agent2.get('ip', '')

                    if agent1_ip and agent2_ip and agent1_ip != agent2_ip:
                        comm_data = {
                            'id': f'n{len(communications)+1}',
                            'local': f"{agent1_ip}:2334",
                            'remote': f"{agent2_ip}:2200",
                            'protocol': 'TCP',
                            'period': 'Yes',
                            'volume': '200',
                            'state': 'Active'
                        }
                        communications.append(comm_data)

        return communications[:10]  # Limit for template

    def generate_detection_data(self, agents_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate placeholder detection data (can be extended with real IDS data)."""
        detections = []

        # Sample detections - in a real implementation, this would come from IDS logs or detection systems
        sample_attacks = [
            ('dos_ip', '192.168.1.100', '192.168.1.1'),
            ('dos_ip', '192.168.1.2', '192.168.1.200'),
        ]

        for attack in sample_attacks:
            detection = {
                'detector': agents_data[0]['agent_id'] if agents_data else 'C1',
                'id': f'd{len(detections)+1}',
                'attack_type': attack[0],
                'attack_source': attack[1],
                'attack_target': attack[2],
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'confidence': '0.5'
            }
            detections.append(detection)

        return detections

    def aggregate_cyber_template(self) -> Dict[str, Any]:
        """Main method to aggregate all data into cyber template."""
        print("Aggregating cyber template data...")

        # Get all agents data
        agents_data = self.get_agents_data()
        print(f"Found {len(agents_data)} agents with data")

        # Process each agent into scanned_nodes format
        scanned_nodes = []
        for i, agent_data in enumerate(agents_data):
            node_id = f"C{i+1}"  # Simple node ID generation

            node = {
                'id': node_id,
                'name': agent_data['name'],
                'description': agent_data['description'],
                'type': agent_data['type'],
                'OS': agent_data['cyber_data']['OS'],
                'lib': agent_data['cyber_data']['lib'],
                'MAC': agent_data['cyber_data']['MAC'],
                'port': agent_data['cyber_data']['port'],
                'vulnerability': agent_data['vulnerabilities'],
                'reachability': []  # Will be filled below
            }
            scanned_nodes.append(node)

        # Generate reachability data
        all_reachability = self.generate_reachability_data(agents_data)
        print(f"Generated {len(all_reachability)} reachability entries")

        # Distribute reachability data among nodes (simplified)
        for i, node in enumerate(scanned_nodes):
            # Assign reachability entries to this node
            node['reachability'] = [
                r for r in all_reachability
                if r['source'] in [port.get('id', '').split(':')[0] for port in node['port']] or
                   any(r['source'] in (iface[0] for iface in agents_data[i]['interfaces'] if iface[0]), False)
            ][:5]  # Limit per node

        # Generate communications and detections
        communications = self.generate_communication_data(agents_data)
        detections = self.generate_detection_data(agents_data)

        print(f"Generated {len(communications)} communication entries")
        print(f"Generated {len(detections)} detection entries")

        # Build final template
        cyber_template = {
            'version': '0.1',
            'system': self.system_name,
            'scanned_nodes': scanned_nodes,
            'communication': communications,
            'detection': detections
        }

        return cyber_template

    def aggregate_cyber_template_sbom_only(self) -> Dict[str, Any]:
        """Aggregate cyber template using only SBOM files (no database)."""
        print("Aggregating cyber template data from SBOM files only...")

        # Get agents data from SBOM files only
        agents_data = self.get_agents_from_sbom_files()
        print(f"Found {len(agents_data)} agents from SBOM files")

        # Process each agent into scanned_nodes format
        scanned_nodes = []
        for i, agent_data in enumerate(agents_data):
            node_id = f"C{i+1}"  # Simple node ID generation

            node = {
                'id': node_id,
                'name': agent_data['name'],
                'description': agent_data['description'],
                'type': agent_data['type'],
                'OS': agent_data['cyber_data']['OS'],
                'lib': agent_data['cyber_data']['lib'],
                'MAC': agent_data['cyber_data']['MAC'],
                'port': agent_data['cyber_data']['port'],
                'vulnerability': agent_data['vulnerabilities'],
                'reachability': []  # Will be filled below
            }
            scanned_nodes.append(node)

        # Generate sample reachability data (limited without network info)
        all_reachability = []
        if len(agents_data) >= 2:
            # Create some sample reachability between first two nodes
            reachability = {
                'target': agents_data[1]['ip'] or '192.168.1.2',
                'source': agents_data[0]['ip'] or '192.168.1.1',
                'type': 'ethernet',
                'direction': 'both'
            }
            all_reachability.append(reachability)
            scanned_nodes[0]['reachability'] = [reachability]

        print(f"Generated {len(all_reachability)} reachability entries")

        # Generate sample communications
        communications = []
        if len(agents_data) >= 2:
            comm_data = {
                'id': 'n1',
                'local': f"{agents_data[0]['ip'] or '192.168.1.1'}:2334",
                'remote': f"{agents_data[1]['ip'] or '192.168.1.2'}:2200",
                'protocol': 'TCP',
                'period': 'Yes',
                'volume': '200',
                'state': 'Active'
            }
            communications.append(comm_data)

        # Generate detections
        detections = self.generate_detection_data(agents_data)

        print(f"Generated {len(communications)} communication entries")
        print(f"Generated {len(detections)} detection entries")

        # Build final template
        cyber_template = {
            'version': '0.1',
            'system': self.system_name,
            'scanned_nodes': scanned_nodes,
            'communication': communications,
            'detection': detections
        }

        return cyber_template

    def save_template(self, template: Dict[str, Any], output_path: str):
        """Save the aggregated template to file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(template, f, indent=2)

        print(f"Cyber template saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Aggregate agent data into cyber template JSON")
    parser.add_argument("-o", "--output", help="Output file path for cyber template")
    parser.add_argument("--standalone", action="store_true", help="Run as standalone script (uses SBOM files only)")
    parser.add_argument("--sbom-only", action="store_true", help="Only process SBOM files, skip database queries")

    args = parser.parse_args()

    if args.standalone and not args.sbom_only:
        try:
            setup_django()
        except ImportError:
            print("Django not available, falling back to SBOM-only mode...")
            args.sbom_only = True

    # Create aggregator and generate template
    aggregator = CyberTemplateAggregator()
    if args.sbom_only:
        template = aggregator.aggregate_cyber_template_sbom_only()
    else:
        template = aggregator.aggregate_cyber_template()

    # Output or save
    if args.output:
        aggregator.save_template(template, args.output)
    else:
        print(json.dumps(template, indent=2))

if __name__ == "__main__":
    main()
