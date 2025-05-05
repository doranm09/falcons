import ipaddress
import subprocess
from django.core.management.base import BaseCommand
from dashboard.models import Node

class Command(BaseCommand):
    help = "Scans a local subnet and populates responsive nodes"

    def add_arguments(self, parser):
        parser.add_argument('cidr', type=str, help="CIDR range to scan (e.g. 10.0.0.0/24)")

    def handle(self, *args, **kwargs):
        cidr_range = kwargs['cidr']
        network = ipaddress.ip_network(cidr_range, strict=False)
        self.stdout.write(f"Scanning network {cidr_range}...")

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
                self.stdout.write(f"[+] {ip_str} is responsive.")
            else:
                self.stdout.write(f"[-] {ip_str} is not responding.")
