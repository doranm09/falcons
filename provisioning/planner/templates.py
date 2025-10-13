from dataclasses import dataclass
from typing import List, Optional


@dataclass
class DiscoveredHost:
    """Represents a host discovered from network scans"""
    host_id: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    os_family: Optional[str] = None
    services: List[str] = None  # e.g., ["ssh","rdp","modbus"]
    tags: List[str] = None      # e.g., ["PLC","DMZ"]
    vlan: Optional[int] = None

    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.tags is None:
            self.tags = []


@dataclass
class PlannedVM:
    """Represents a VM planned for provisioning"""
    name: str
    template: str
    image_path: str
    memory_mb: int
    vcpus: int
    vlan: int
    ovs_bridge: str
    ip: Optional[str] = None
    virtio_ports: List[str] = None

    def __post_init__(self):
        if self.virtio_ports is None:
            self.virtio_ports = []
