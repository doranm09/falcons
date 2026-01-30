import re
from typing import Dict, Iterable, List


def _sanitize_vm_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", name or "").strip("-").lower()
    return cleaned or "node"


def build_minimega_script(nodes: Iterable[Dict[str, str]], disk_image: str, vlan: str, enable_virtio: bool, memory_mb: int) -> str:
    lines: List[str] = [
        "clear vm config",
        f"vm config memory {memory_mb}",
        f"vm config net {vlan}",
    ]

    if enable_virtio:
        lines.append("vm config virtio-ports cc")

    used_names = set()

    for node in nodes:
        raw_name = node.get("name") or node.get("ip") or "node"
        base_name = _sanitize_vm_name(raw_name)
        vm_name = base_name
        counter = 2
        while vm_name in used_names:
            vm_name = f"{base_name}-{counter}"
            counter += 1
        used_names.add(vm_name)

        comment = f"# {node.get('ip', 'unknown')} {node.get('name', '')}".strip()
        if node.get("os"):
            comment += f" | {node['os']}"
        if node.get("packages") is not None:
            comment += f" | packages={node['packages']}"

        lines.extend([
            "",
            comment,
            f"vm config disk {disk_image}",
            f"vm launch kvm {vm_name}",
        ])

    lines.append("")
    lines.append("vm start all")
    return "\n".join(lines)


def build_digital_twin_manifest(scan_id: int, nodes: List[Dict[str, str]], links: List[Dict[str, str]],
                                disk_image: str, vlan: str, enable_virtio: bool, memory_mb: int) -> Dict[str, object]:
    return {
        "scan_id": scan_id,
        "nodes": nodes,
        "links": links,
        "minimega": {
            "disk_image": disk_image,
            "vlan": vlan,
            "enable_virtio": enable_virtio,
            "memory_mb": memory_mb,
        },
    }
