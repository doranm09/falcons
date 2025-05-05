from celery import shared_task
import ipaddress
import subprocess
from .models import Node

@shared_task(bind=True)
def scan_network_task(self, cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"error": "Invalid CIDR"}

    count = 0
    for ip in network.hosts():
        ip_str = str(ip)
        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip_str],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            node, created = Node.objects.get_or_create(
                ip_address=ip_str,
                defaults={'name': f"Host-{ip_str}", 'status': 'online'}
            )
            if not created:
                node.status = 'online'
                node.save()
            count += 1

    return {"success": f"Scan complete. {count} hosts online."}
