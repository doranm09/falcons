"""VM planning logic combining templates and network configuration."""

from typing import List, Dict, Any, Optional, Iterator
from ..planner.templates import DiscoveredHost, PlannedVM
from .templates_mapper import TemplateMapper
from .network_plan import NetworkPlanner
import os


class VMPlanner:
    """Plans VMs from discovered hosts using templates and network planning."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.templates_mapper = TemplateMapper(config)
        self.network_planner = NetworkPlanner(config)
        self.defaults = config.get("defaults", {})
        self.run_label = self.defaults.get("run_label", "scan-provision")

    def plan_vms(self, hosts: List[DiscoveredHost]) -> List[PlannedVM]:
        """Plan VMs from discovered hosts."""
        vms = []

        # Group hosts by template to reuse network resources efficiently
        template_groups: Dict[str, List[DiscoveredHost]] = {}

        for host in hosts:
            template_name = self.templates_mapper.resolve_template(host)
            if template_name is None:
                # Skip hosts that don't match any template
                continue

            if template_name not in template_groups:
                template_groups[template_name] = []
            template_groups[template_name].append(host)

        # Plan VMs for each template group
        for template_name, group_hosts in template_groups.items():
            template_config = self.templates_mapper.get_template_config(template_name)

            # Get IPs for this group
            ips = self.network_planner.plan_ips(group_hosts, len(group_hosts))

            for i, (host, ip) in enumerate(zip(group_hosts, ips)):
                vm = self._create_planned_vm(host, template_name, template_config, ip, i)
                if vm:
                    vms.append(vm)

        return vms

    def _create_planned_vm(self, host: DiscoveredHost, template_name: str,
                          template_config: Dict[str, Any], ip: Optional[str],
                          index: int) -> Optional[PlannedVM]:
        """Create a PlannedVM from host and configuration."""
        try:
            # Generate unique VM name
            vm_name = f"{self.run_label}-{template_name}-{index:02d}"

            # Get image path - use snapshot directory for cloned images
            snapshot_dir = self.defaults.get("snapshot_dir", "/var/lib/minimega/snapshots")
            base_image = template_config.get("image", f"base-{template_name}.qcow2")

            # Create snapshot-style image path following docs/minimega/create_snapshot_images.md
            image_path = os.path.join(snapshot_dir, f"{template_name}-snap.qcow2")

            # Get memory and vcpus
            memory_mb = template_config.get("memory_mb", 2048)
            vcpus = template_config.get("vcpus", 2)

            # Network planning
            vlan = self.network_planner.plan_vlan(host)
            ovs_bridge = self.network_planner.get_bridge()

            # Virtio serial ports if enabled
            virtio_ports = []
            if template_config.get("enable_virtio_serial", True):
                ports_config = template_config.get("virtio_ports", [])
                virtio_ports.extend(ports_config)

            return PlannedVM(
                name=vm_name,
                template=template_name,
                image_path=image_path,
                memory_mb=memory_mb,
                vcpus=vcpus,
                vlan=vlan,
                ovs_bridge=ovs_bridge,
                ip=ip,
                virtio_ports=virtio_ports
            )

        except Exception as e:
            # Log error but continue processing other VMs
            print(f"Error planning VM for host {host.host_id}: {e}")
            return None
