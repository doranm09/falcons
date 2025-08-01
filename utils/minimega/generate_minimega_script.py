import argparse
from pathlib import Path

def generate_minimega_script(vm_count, vlan, disk_image, output_file="launch_vms.mm", enable_virtio=False):
    """
    Generate a MiniMega script to launch multiple VMs with optional virtio-serial support.
    """
    lines = [
        "clear vm config",
        "vm config memory 2048",
        f"vm config net {vlan}",
    ]

    if enable_virtio:
        lines.append("vm config virtio-ports cc")

    for i in range(1, vm_count + 1):
        vm_name = f"vm{str(i).zfill(2)}"
        lines += [
            "",
            f"vm config disk {disk_image}",
            f"vm launch kvm {vm_name}"
        ]

    lines.append("\nvm start all")

    Path(output_file).write_text("\n".join(lines))
    print(f"[+] Script generated: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate MiniMega VM launch script.")
    parser.add_argument("--count", type=int, default=2, help="Number of VMs to create (default: 2)")
    parser.add_argument("--vlan", type=str, default="100", help="VLAN to connect VMs to (default: 100)")
    parser.add_argument("--disk", type=str, required=True, help="Path to the VM disk image (.qcow2)")
    parser.add_argument("--output", type=str, default="launch_vms.mm", help="Output script file (default: launch_vms.mm)")
    parser.add_argument("--virtio", action="store_true", help="Enable virtio-ports for miniccc (/dev/virtio-ports/cc)")
    args = parser.parse_args()

    generate_minimega_script(args.count, args.vlan, args.disk, args.output, args.virtio)
