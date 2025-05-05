from django.db import models

class Node(models.Model):
    name = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField(protocol='IPv4')
    status = models.CharField(max_length=20, choices=[
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('degraded', 'Degraded')
    ])
    last_heartbeat = models.DateTimeField(auto_now=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class Link(models.Model):
    source = models.ForeignKey(Node, related_name='links_from', on_delete=models.CASCADE)
    destination = models.ForeignKey(Node, related_name='links_to', on_delete=models.CASCADE)
    weight = models.FloatField()  # e.g., ping latency or static cost