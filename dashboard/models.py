from django.db import models
from django.utils import timezone


class ScanRun(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    cidr = models.CharField(max_length=64)
    status = models.CharField(max_length=32, default='PENDING')  # or 'COMPLETE', 'FAILED'
    result_summary = models.TextField(blank=True, null=True)
    openvas_task_id = models.CharField(max_length=64, null=True, blank=True)
    scan_type = models.CharField(max_length=32, default="ping") # ping or openvas

    def __str__(self):
        return f"Scan on {self.cidr} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

class Node(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="nodes", null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=32, default="online")
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    description = models.TextField(blank=True)
    agent_id = models.CharField(max_length=64, unique=True, null=True, blank=True)  # New

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class NodeInterface(models.Model):
    node = models.ForeignKey(Node, on_delete=models.CASCADE, related_name="interfaces")
    name = models.CharField(max_length=64)
    ip = models.GenericIPAddressField()
    mac = models.CharField(max_length=64)

    def __str__(self):
        return f"{self.node.name} - {self.name} ({self.ip})"


class Link(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="links", null=True)
    source = models.ForeignKey(Node, related_name='links_from', on_delete=models.CASCADE)
    destination = models.ForeignKey(Node, related_name='links_to', on_delete=models.CASCADE)
    weight = models.FloatField()

class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=32, unique=True)
    description = models.TextField()
    severity = models.CharField(max_length=16, blank=True)
    score = models.FloatField(null=True, blank=True)
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    references = models.TextField(blank=True)
    nodes = models.ManyToManyField(Node, blank=True)

    def __str__(self):
        return f"{self.cve_id} ({self.severity})"

class AgentCommand(models.Model):
    agent_id = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    parameters = models.JSONField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    acknowledged = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.agent_id} - {self.action}"


class CommandResult(models.Model):
    command = models.ForeignKey(AgentCommand, on_delete=models.CASCADE)
    agent_id = models.CharField(max_length=64)
    output = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


class Vulernability(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="vulnerabilities")
    host_ip = models.GenericIPAddressField()
    cve_id = models.CharField(max_length=32)
    name = models.CharField(max_length=255)
    severity = models.FloatField()
    description = models.TextField()
    description = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["host_ip", "cve_id"])]

    def __str__(self):
        return f"{self.cve_id} on {self.host_ip} ({self.severity})"