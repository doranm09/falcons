"""Command-line interface for VM provisioning from network scans."""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any

# Import dataclasses first
from .planner.templates import DiscoveredHost

# Local imports
from .scan_ingest.dashboard_json import parse_dashboard_json
from .planner.vm_plan import VMPlanner
from .planner.templates_mapper import TemplateMapper
from .emitters.minimega_wrapper import MiniMegaEmitter
from .executor.run_minimega import MiniMegaRunner
from .executor.state import StateManager


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML not installed. Install with: pip install PyYAML")
        sys.exit(1)

    config_file = Path(config_path)
    if not config_file.exists():
        print(f"ERROR: Config file not found: {config_path}")
        sys.exit(1)

    try:
        return yaml.safe_load(config_file.read_text())
    except Exception as e:
        print(f"ERROR: Failed to parse config: {e}")
        sys.exit(1)


def ingest_command(args):
    """Handle 'ingest' subcommand."""
    config = load_config(args.config)

    # Load and parse JSON data
    json_file = Path(args.file)
    if not json_file.exists():
        print(f"ERROR: Input file not found: {args.file}")
        return

    try:
        json_data = json.loads(json_file.read_text())
    except Exception as e:
        print(f"ERROR: Failed to parse JSON: {e}")
        return

    # Parse hosts based on format
    if args.format == "dashboard":
        hosts = parse_dashboard_json(json_data)
    else:
        print(f"ERROR: Unsupported format: {args.format}")
        return

    # Save to output file
    output_data = {
        "meta": {
            "format": args.format,
            "input_file": str(json_file),
            "host_count": len(hosts)
        },
        "hosts": [
            {
                "host_id": h.host_id,
                "ip": h.ip,
                "mac": h.mac,
                "os_family": h.os_family,
                "services": h.services,
                "tags": h.tags,
                "vlan": h.vlan
            }
            for h in hosts
        ]
    }

    output_file = Path(args.out)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(output_data, indent=2))
    print(f"Saved {len(hosts)} hosts to {args.out}")


def plan_command(args):
    """Handle 'plan' subcommand."""
    config = load_config(args.config)

    # Load hosts from JSON
    hosts_file = Path(args.hosts)
    if not hosts_file.exists():
        print(f"ERROR: Hosts file not found: {args.hosts}")
        return

    try:
        data = json.loads(hosts_file.read_text())
        hosts = []
        for h in data['hosts']:
            # Debug template matching
            host_obj = DiscoveredHost(
                host_id=h['host_id'],
                ip=h['ip'],
                mac=h['mac'],
                os_family=h['os_family'],
                services=h['services'],
                tags=h['tags'],
                vlan=h['vlan']
            )

            # Print debug info
            print(f"Host {host_obj.host_id}: OS={host_obj.os_family}, Services={host_obj.services}, Tags={host_obj.tags}")

            mapper = TemplateMapper(config)
            template = mapper.resolve_template(host_obj)
            print(f"  -> Template: {template}")

            hosts.append(host_obj)
    except Exception as e:
        print(f"ERROR: Failed to load hosts: {e}")
        return

    # Plan VMs
    planner = VMPlanner(config)
    vms = planner.plan_vms(hosts)

    # Save plan
    plan_data = {
        "meta": {
            "input_file": str(hosts_file),
            "vm_count": len(vms),
            "run_label": config.get("defaults", {}).get("run_label", "scan-provision")
        },
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

    output_file = Path(args.out)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(plan_data, indent=2))
    print(f"Planned {len(vms)} VMs for {len(hosts)} hosts, saved to {args.out}")


def emit_command(args):
    """Handle 'emit' subcommand."""
    config = load_config(args.config)

    # Load plan from JSON
    plan_file = Path(args.plan)
    if not plan_file.exists():
        print(f"ERROR: Plan file not found: {args.plan}")
        return

    try:
        plan_data = json.loads(plan_file.read_text())
        vms = [
            type('PlannedVM', (), {
                'name': vm['name'],
                'template': vm['template'],
                'image_path': vm['image_path'],
                'memory_mb': vm['memory_mb'],
                'vcpus': vm['vcpus'],
                'vlan': vm['vlan'],
                'ovs_bridge': vm['ovs_bridge'],
                'ip': vm['ip'],
                'virtio_ports': vm['virtio_ports']
            })()
            for vm in plan_data['vms']
        ]
    except Exception as e:
        print(f"ERROR: Failed to load plan: {e}")
        return

    if not vms:
        print("ERROR: No VMs in plan")
        return

    # Generate MiniMega script
    emitter = MiniMegaEmitter(config)
    mm_file = emitter.generate_script(vms)

    print(f"Generated MiniMega script: {mm_file}")


def apply_command(args):
    """Handle 'apply' subcommand."""
    config = load_config(args.config)

    mm_file = Path(args.mm)
    if not mm_file.exists():
        print(f"ERROR: MM file not found: {args.mm}")
        return

    # Run the script
    dry_run = getattr(args, 'dry_run', config.get("safety", {}).get("dry_run", False))

    runner = MiniMegaRunner(config)
    run_label = config.get("defaults", {}).get("run_label", "scan-provision")

    result = runner.run_script(str(mm_file), run_label, dry_run=dry_run)

    if result["success"]:
        if dry_run:
            print("Dry run completed successfully")
        else:
            print(f"VM provisioning completed. Run log: {runner.run_output_dir}/run_{run_label}_{result['timestamp'][:19].replace(':', '-')}.json")

            # Record in state if we have the VMs info
            # For now, assume successful provision
            # state_mgr = StateManager(config)
            # state_mgr.record_provisioned_vms(vms, f"run_{timestamp}")
    else:
        print(f"ERROR: Execution failed: {result['stderr']}")
        sys.exit(1)


def destroy_command(args):
    """Handle 'destroy' subcommand."""
    config = load_config(args.config)

    state_mgr = StateManager(config)
    label = getattr(args, 'label', None) or config.get("defaults", {}).get("run_label", "scan-provision")

    try:
        teardown_script = state_mgr.teardown_run(label)
        print(f"Generated teardown script: {teardown_script}")

        if getattr(args, 'execute', False):
            runner = MiniMegaRunner(config)
            result = runner.run_script(teardown_script, f"teardown_{label}", dry_run=False)
            if result["success"]:
                print("Successfully destroyed VMs")
                # Update state
                if label in state_mgr.inventory:
                    del state_mgr.inventory[label]
                    state_mgr._save_inventory()
            else:
                print(f"ERROR: Teardown failed: {result['stderr']}")
                sys.exit(1)

    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Dynamic VM provisioning from network scans",
        prog="python -m provisioning"
    )
    parser.add_argument(
        "--config",
        default="configs/provisioning.example.yaml",
        help="Configuration file path"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Parse scan results into host data"
    )
    ingest_parser.add_argument(
        "--format", choices=["nmap", "openvas", "dashboard"], required=True,
        help="Input scan format"
    )
    ingest_parser.add_argument(
        "--file", required=True,
        help="Input scan file path"
    )
    ingest_parser.add_argument(
        "--out", required=True,
        help="Output hosts file path"
    )

    # Plan command
    plan_parser = subparsers.add_parser(
        "plan",
        help="Plan VMs from host data"
    )
    plan_parser.add_argument(
        "--hosts", required=True,
        help="Input hosts file (from ingest)"
    )
    plan_parser.add_argument(
        "--out", required=True,
        help="Output plan file path"
    )

    # Emit command
    emit_parser = subparsers.add_parser(
        "emit",
        help="Generate MiniMega script from plan"
    )
    emit_parser.add_argument(
        "--plan", required=True,
        help="Input plan file"
    )

    # Apply command
    apply_parser = subparsers.add_parser(
        "apply",
        help="Execute MiniMega script to provision VMs"
    )
    apply_parser.add_argument(
        "--mm", required=True,
        help="MiniMega script file path"
    )
    apply_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print script instead of executing"
    )

    # Destroy command
    destroy_parser = subparsers.add_parser(
        "destroy",
        help="Generate and optionally execute teardown script"
    )
    destroy_parser.add_argument(
        "--label",
        help="Run label to destroy (default: from config)"
    )
    destroy_parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute teardown immediately"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Dispatch to command handler
    if args.command == "ingest":
        ingest_command(args)
    elif args.command == "plan":
        plan_command(args)
    elif args.command == "emit":
        emit_command(args)
    elif args.command == "apply":
        apply_command(args)
    elif args.command == "destroy":
        destroy_command(args)


if __name__ == "__main__":
    main()
