from django.db import models
from django.utils import timezone


class ScanRun(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    cidr = models.CharField(max_length=64)
    status = models.CharField(max_length=32, default='PENDING')  # or 'COMPLETE', 'FAILED'
    result_summary = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Scan on {self.cidr} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

class Node(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="nodes", null=True)
    ip_address = models.GenericIPAddressField()
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=32, default="online")
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

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

