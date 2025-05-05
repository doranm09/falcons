# dashboard/tasks.py
from celery import shared_task
from .models import Node
import subprocess
import ipaddress

@shared_task(bind=True)
def scan_network_task(self, cidr):
    nodes_found = []
    for ip in ipaddress.IPv4Network(cidr, strict=False):
        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                stdout=subprocess.DEVNULL)
        if result.returncode == 0:
            node = Node.objects.create(ip_address=str(ip), name=str(ip))
            nodes_found.append(str(ip))
    return nodes_found  # This will be available via `/scan/status/<task_id>/`
