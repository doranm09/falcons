"""Wrapper for generating MiniMega scripts from planned VMs."""

from datetime import datetime
from pathlib import Path
from typing import List
from ..planner.templates import PlannedVM


class MiniMegaEmitter:
    """Generates MiniMega .mm script files from planned VMs."""

    def __init__(self, config: dict):
        self.config = config
        self.defaults = config.get("defaults", {})
        self.mm_output_dir = Path(self.defaults.get("mm_output_dir", "./out/mm"))
        self.mm_output_dir.mkdir(parents=True, exist_ok=True)

    def generate_script(self, vms: List[PlannedVM]) -> str:
        """Generate MiniMega script for the given VMs."""
        if not vms:
            raise ValueError("No VMs to generate script for")

        # Start with clear namespace
        lines = [
            "clear"  # Clear all configurations
        ]

        # Group by VLAN for efficiency (but current MiniMega seems to config per VM)
        # For now, generate per-VM blocks following the example pattern

        for vm in vms:
            vm_lines = self._generate_vm_block(vm)
            lines.extend(vm_lines)

        # Start all VMs at the end
        lines.append("")
        lines.append("vm start all")

        # Write to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.mm_output_dir / f"run_{timestamp}.mm"
        output_path.write_text("\n".join(lines) + "\n")

        return str(output_path)

    def _generate_vm_block(self, vm: PlannedVM) -> List[str]:
        """Generate MiniMega config block for a single VM."""
        lines = [
            "",
            f"vm config memory {vm.memory_mb}",
            f"vm config vcpus {vm.vcpus}",
            f"vm config bridge {vm.ovs_bridge}",
            f"vm config vlan {vm.vlan}",
        ]

        # Add virtio ports
        for port in vm.virtio_ports:
            lines.append(f"vm config virtio-ports {port}")

        lines.extend([
            f"vm config disk {vm.image_path}",
            f"vm launch kvm {vm.name}"
        ])

        return lines
