"""VM inventory and state management for idempotent operations."""

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
from ..planner.templates import PlannedVM


class StateManager:
    """Manages inventory of provisioned VMs and supports teardown operations."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.state_dir = Path("./out/state")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.inventory_file = self.state_dir / "inventory.json"

        # Load existing inventory
        self.inventory = self._load_inventory()
        self.run_label = config.get("defaults", {}).get("run_label", "scan-provision")

    def record_provisioned_vms(self, vms: List[PlannedVM], run_id: str) -> None:
        """Record provisioned VMs in inventory."""
        run_entry = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "run_label": self.run_label,
            "vms": [
                {
                    "name": vm.name,
                    "template": vm.template,
                    "image_path": vm.image_path,
                    "memory_mb": vm.memory_mb,
                    "vcpus": vm.vcpus,
                    "vlan": vm.vlan,
                    "ovs_bridge": vm.ovs_bridge,
                    "ip": vm.ip,
                    "virtio_ports": vm.virtio_ports
                }
                for vm in vms
            ]
        }

        if self.run_label not in self.inventory:
            self.inventory[self.run_label] = []

        self.inventory[self.run_label].append(run_entry)
        self._save_inventory()

    def get_provisioned_vms(self, run_label: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of provisioned VMs for a run label."""
        label = run_label or self.run_label
        if label not in self.inventory:
            return []

        # Return VMs from the most recent run
        runs = self.inventory[label]
        if not runs:
            return []

        latest_run = max(runs, key=lambda r: r["timestamp"])
        return latest_run["vms"]

    def teardown_run(self, run_label: Optional[str] = None, force: bool = False) -> str:
        """
        Generate teardown script for all VMs in a run label.

        Returns path to teardown .mm script.
        """
        label = run_label or self.run_label
        vms = self.get_provisioned_vms(label)

        if not vms and not force:
            raise ValueError(f"No VMs found for run label '{label}'")

        # Generate teardown script
        teardown_lines = [
            "# Teardown script generated automatically",
            "clear"
        ]

        # Kill and clear VMs
        for vm in vms:
            teardown_lines.extend([
                f"vm kill {vm['name']}",
                f"vm clear {vm['name']}"
            ])

        # Save teardown script
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        teardown_file = self.state_dir / f"teardown_{label}_{timestamp}.mm"

        teardown_file.write_text("\n".join(teardown_lines) + "\n")

        return str(teardown_file)

    def list_runs(self) -> Dict[str, List[str]]:
        """List available run labels and their timestamps."""
        return {
            label: [run["timestamp"] for run in runs]
            for label, runs in self.inventory.items()
        }

    def _load_inventory(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load inventory from file."""
        if self.inventory_file.exists():
            try:
                with open(self.inventory_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                # Start with empty inventory if file is corrupted
                return {}
        return {}

    def _save_inventory(self) -> None:
        """Save inventory to file."""
        with open(self.inventory_file, 'w') as f:
            json.dump(self.inventory, f, indent=2)
