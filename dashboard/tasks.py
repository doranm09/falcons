# dashboard/tasks.py
from celery import shared_task
from .models import Node, Link
import subprocess
import ipaddress

@shared_task
def scan_network_task(cidr):
    from .models import ScanRun, Node, Link  # ensure local import in tasks
    import subprocess, ipaddress

    scan = ScanRun.objects.create(cidr=cidr, status="STARTED")

    network = ipaddress.ip_network(cidr, strict=False)
    found_nodes = []

    for ip in network.hosts():
        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            latency = parse_ping_latency(result.stdout)
            node = Node.objects.create(
                scan_run=scan,
                ip_address=str(ip),
                name=str(ip)
            )
            found_nodes.append((node, latency))

    # Create weighted links between nodes
    for i in range(len(found_nodes)):
        for j in range(i + 1, len(found_nodes)):
            node1, latency1 = found_nodes[i]
            node2, latency2 = found_nodes[j]
            avg_latency = (latency1 + latency2) / 2
            Link.objects.create(scan_run=scan, source=node1, destination=node2, weight=avg_latency)
            Link.objects.create(scan_run=scan, source=node2, destination=node1, weight=avg_latency)

    scan.status = "COMPLETE"
    scan.result_summary = f"{len(found_nodes)} nodes, {len(found_nodes)*(len(found_nodes)-1)} links"
    scan.save()

    return scan.result_summary

def parse_ping_latency(output):
    for line in output.decode().splitlines():
        if 'time=' in line:
            try:
                return float(line.split('time=')[-1].split()[0])
            except:
                pass
    return 100.0  # Fallback default
