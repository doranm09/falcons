#!/usr/bin/env python3
"""
extract_sbom_to_template.py — Process SBOM data and produce the full cyber template
containing system information, package details, network interfaces, and processes.

This script extracts data from CycloneDX SBOM format and populates the full cyber template
structure used by the cyber penetration testing framework.
"""

import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

def extract_packages_from_sbom(sbom_data: Dict[str, Any]) -> List[str]:
    """
    Extract package information from CycloneDX SBOM and format for cyber template.

    Args:
        sbom_data: Parsed CycloneDX SBOM data

    Returns:
        List of formatted package strings for the template
    """
    packages = []

    components = sbom_data.get("components", [])
    for component in components:
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")

        # Extract package type from purl
        pkg_type = "unknown"
        if purl:
            if purl.startswith("pkg:deb/"):
                pkg_type = "deb"
            elif purl.startswith("pkg:rpm/"):
                pkg_type = "rpm"
            elif "msi" in purl.lower() or "windows" in purl.lower():
                pkg_type = "windows"
            else:
                pkg_type = "generic"

        # Format as dictionary string like in the template
        pkg_dict = f"{{'name': '{name}', 'version': '{version}', 'type': '{pkg_type}'}}"
        packages.append(pkg_dict)

    return packages

def extract_os_metadata_from_sbom(sbom_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract OS metadata from SBOM.

    Args:
        sbom_data: Parsed CycloneDX SBOM data

    Returns:
        Dictionary with OS name and version
    """
    metadata = sbom_data.get("metadata", {})
    component = metadata.get("component", {})

    if component.get("type") == "operating-system":
        name = component.get("name", "unknown")
        version = component.get("version", "unknown")
    else:
        # Fallback - try to parse from components
        name = "unknown"
        version = "unknown"
        for comp in sbom_data.get("components", [])[:10]:  # Check first few components
            if comp.get("type") == "operating-system":
                name = comp.get("name", "unknown")
                version = comp.get("version", "unknown")
                break

    return {"name": name, "version": version}

def load_sample_system_info() -> Dict[str, Any]:
    """
    Load sample system information structure.
    In a real implementation, this would be collected from the actual system.
    """
    return {
        "agent_id": "193853668050576",
        "hostname": "MEL05280D.me.gatech.edu",
        "os": "Linux",
        "os_version": "#32~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Sep  2 14:21:04 UTC 2",
        "platform": "Linux-6.14.0-32-generic-x86_64-with-glibc2.39",
        "cpu_count": 36,
        "memory_total": 134758199296,
        "interfaces": [
            {
                "name": "lo",
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00"
            },
            {
                "name": "eno1",
                "ip": "128.61.144.211",
                "mac": "b0:4f:13:05:c6:90"
            }
        ],
        "processes": [
            {
                "pid": 1,
                "name": "systemd"
            },
            {
                "pid": 2,
                "name": "kthreadd"
            }
        ]
    }

def load_sample_network_data() -> Dict[str, Any]:
    """
    Load sample network interface and connection data.
    In a real implementation, this would be collected from psutil and netifaces.
    """
    return {
        "MAC": [
            "b0:4f:13:05:c6:90",
            "80:6d:97:56:e5:e3",
            "80:6d:97:42:4b:c3",
            "80:6d:97:56:e3:73"
        ],
        "port": [
            {
                "id": "128.61.144.211:52944",
                "Protocol": "TCP"
            },
            {
                "id": "127.0.0.1:9392",
                "Protocol": "TCP"
            },
            {
                "id": "::1:53",
                "Protocol": "TCP"
            }
        ]
    }

def extract_sbom_and_create_cyber_template(sbom_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Main function to extract data from SBOM and create complete cyber template.

    Args:
        sbom_path: Path to CycloneDX SBOM JSON file
        output_path: Optional output path for the generated template

    Returns:
        Complete cyber template dictionary
    """

    # Load SBOM data
    with open(sbom_path, 'r') as f:
        sbom_data = json.load(f)

    print(f"[extract] Processing SBOM: {sbom_path}")
    print(f"[extract] Found {len(sbom_data.get('components', []))} components")

    # Extract OS information
    os_info = extract_os_metadata_from_sbom(sbom_data)
    os_string = f"Ubuntu {os_info['version']} {os_info['version']} ({os_info['name']})"

    # Extract packages
    installed_packages = extract_packages_from_sbom(sbom_data)

    # Load sample system and network data
    # In production, these would be collected live from the system
    system_info = load_sample_system_info()
    network_data = load_sample_network_data()

    # Construct the full cyber template
    cyber_template = {
        "cyber_template_data": {
            "OS": os_string,
            "lib": installed_packages[:100],  # Limit to first 100 for template (like existing example)
            "MAC": network_data["MAC"],
            "port": network_data["port"]
        },
        "system_info": system_info,
        "collection_timestamp": datetime.now().isoformat()
    }

    print(f"[extract] Extracted {len(installed_packages)} packages")
    print(f"[extract] Template created with {len(cyber_template['cyber_template_data']['lib'])} packages shown")

    # Save if output path provided
    if output_path:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(cyber_template, f, indent=2)

        print(f"[extract] Cyber template saved to: {output_file}")

    return cyber_template

def main():
    parser = argparse.ArgumentParser(description="Extract SBOM data and produce full cyber template")
    parser.add_argument("sbom_file", help="Path to CycloneDX SBOM JSON file")
    parser.add_argument("-o", "--output", help="Output path for cyber template JSON file")
    parser.add_argument("--template-only", action="store_true",
                       help="Output only cyber_template_data section (legacy format)")

    args = parser.parse_args()

    try:
        # Extract SBOM and create template
        cyber_template_full = extract_sbom_and_create_cyber_template(args.sbom_file, args.output)

        # Output format based on flag
        if args.template_only:
            # Output legacy format (just cyber_template_data)
            output_data = cyber_template_full["cyber_template_data"]
        else:
            # Output full format with system_info
            output_data = cyber_template_full

        # Print to stdout if no output file specified
        if not args.output:
            print(json.dumps(output_data, indent=2))

    except FileNotFoundError:
        print(f"ERROR: SBOM file not found: {args.sbom_file}", file=sys.stderr)
        exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in SBOM file: {e}", file=sys.stderr)
        exit(1)
    except Exception as e:
        print(f"ERROR: Processing failed: {e}", file=sys.stderr)
        exit(1)

if __name__ == "__main__":
    main()
