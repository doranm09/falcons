"""Ingest hosts from dashboard JSON format."""

import json
from typing import List
from ..planner.templates import DiscoveredHost


def parse_dashboard_json(json_data: dict) -> List[DiscoveredHost]:
    """
    Parse dashboard JSON format into DiscoveredHost objects.

    Expected format: {
        "cyber_template_data": {
            "OS": "string",
            "MAC": ["mac1", "mac2", ...],
            "lib": [...],
            "port": [{"id": "ip:port", "Protocol": "TCP/UDP"}, ...]
        },
        "system_info": {
            "agent_id": "string",
            "hostname": "string",
            "interfaces": [{"name": "string", "ip": "string", "mac": "string"}, ...]
        }
    }

    Returns hosts based on discovered network interfaces/services.
    """
    hosts = []

    system_info = json_data.get("system_info", {})
    cyber_template_data = json_data.get("cyber_template_data", {})

    # Create a host from system_info which represents the current scanned host
    agent_id = system_info.get("agent_id", "unknown")
    hostname = system_info.get("hostname", "unknown")
    os_info = cyber_template_data.get("OS", "")

    # Extract interfaces
    interfaces = system_info.get("interfaces", [])

    # Extract ports and map to services
    ports = cyber_template_data.get("port", [])
    services = []
    for port_entry in ports:
        port_id = port_entry.get("id", "")
        protocol = port_entry.get("Protocol", "")
        if ":" in port_id and protocol.upper() == "TCP":
            # Extract port number or known service names
            try:
                # ip:port format
                parts = port_id.split(":")
                if len(parts) >= 2:
                    port_num = int(parts[-1])
                    # Basic service mapping
                    if port_num == 22:
                        services.append("ssh")
                    elif port_num == 80:
                        services.append("http")
                    elif port_num == 443:
                        services.append("https")
                    elif port_num == 53:
                        services.append("dns")
                    elif port_num == 631:
                        services.append("ipp")
                    elif port_num == 53 and "::1" in port_id:
                        services.append("dns")
                    # Add more service mappings as needed
            except (ValueError, IndexError):
                pass

    # Create host for each interface that has an IP
    for iface in interfaces:
        iface_name = iface.get("name", "")
        ip = iface.get("ip", "")
        mac = iface.get("mac", "")

        # Skip loopback (can't virtualize)
        if iface_name == "lo" or ip in ["127.0.0.1", "::1"]:
            continue

        # Create a unique host_id
        host_id = f"{agent_id}_{iface_name}"

        # Determine OS family from OS string (basic)
        os_family = None
        os_lower = os_info.lower()
        if "ubuntu" in os_lower or "debian" in os_lower:
            os_family = "Linux"
        elif "windows" in os_lower:
            os_family = "Windows"

        # Basic tags from network configuration
        tags = []
        if "br-" in iface_name:  # Docker bridge
            tags.append("docker")
        elif "enx" in iface_name:  # USB Ethernet
            tags.append("usb")

        # Create host if we have an IP
        if ip:
            host = DiscoveredHost(
                host_id=host_id,
                interface_name=iface_name,
                ip=ip,
                mac=mac,
                os_family=os_family,
                services=services[:],  # copy services
                tags=tags
            )
            hosts.append(host)

    return hosts
