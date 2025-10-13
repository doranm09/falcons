"""Network planning logic for VMs."""

import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from ..planner.templates import DiscoveredHost


class NetworkPlanner:
    """Plans network configuration (IP addresses, VLANs) for VMs."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.networking_config = config.get("networking", {})
        self.reserve_ips = self.networking_config.get("reserve_static_ips", True)

        # IP planning
        ip_plan = self.networking_config.get("ip_plan", {})
        self.subnet = ipaddress.ip_network(ip_plan.get("subnet", "10.200.0.0/16"))
        self.ip_offset = ip_plan.get("start_offset", 100)

        # Track used IPs
        self.used_ips = set()

    def plan_vlan(self, host: DiscoveredHost) -> int:
        """Determine VLAN for a host."""
        # Use host's VLAN if available, otherwise from defaults
        if host.vlan is not None:
            return host.vlan

        return self.config.get("defaults", {}).get("vlan", 200)

    def plan_ips(self, hosts: List[DiscoveredHost], count: int) -> List[Optional[str]]:
        """Plan IP addresses for VMs. Returns list of IPs or None."""
        if not self.reserve_ips:
            return [None] * count

        ips = []
        subnet_hosts = list(self.subnet.hosts())

        for _ in range(count):
            ip = self._allocate_ip(subnet_hosts)
            ips.append(str(ip) if ip else None)

        return ips

    def _allocate_ip(self, subnet_hosts: List[ipaddress.IPv4Address]) -> Optional[ipaddress.IPv4Address]:
        """Allocate next available IP address."""
        # Start from offset
        for host_addr in subnet_hosts[self.ip_offset:]:
            if str(host_addr) not in self.used_ips:
                self.used_ips.add(str(host_addr))
                return host_addr
        return None

    def get_bridge(self) -> str:
        """Get default OVS bridge name."""
        return self.config.get("defaults", {}).get("ovs_bridge", "br-int")
