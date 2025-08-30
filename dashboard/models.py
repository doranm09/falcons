from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator

# -----------------------------
# Common choices / helpers
# -----------------------------
SCAN_STATUS_CHOICES = [
    ("PENDING", "Pending"),
    ("RUNNING", "Running"),
    ("COMPLETE", "Complete"),
    ("FAILED", "Failed"),
]

SCAN_TYPE_CHOICES = [
    ("ping", "Ping"),
    ("openvas", "OpenVAS"),
]

SEVERITY_CHOICES = [
    ("None", "None"),
    ("Low", "Low"),
    ("Medium", "Medium"),
    ("High", "High"),
    ("Critical", "Critical"),
]


# -----------------------------
# Inventory / Scans
# -----------------------------
class ScanRun(models.Model):
    class Status(models.TextChoices):
        IN_PROGRESS = "IN_PROGRESS"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"

    timestamp = models.DateTimeField(default=timezone.now)
    cidr = models.CharField(max_length=64)
    status = models.CharField(max_length=32, choices=SCAN_STATUS_CHOICES, default="PENDING")
    result_summary = models.TextField(blank=True, null=True)
    openvas_task_id = models.CharField(max_length=64, null=True, blank=True)
    scan_type = models.CharField(max_length=32, choices=SCAN_TYPE_CHOICES, default="ping")

    class Meta:
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["status", "scan_type"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self):
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"Scan on {self.cidr} at {ts}"


class Node(models.Model):
    # Networked endpoint discovered by scans (global inventory or per-run via scan_run FK)
    scan_run = models.ForeignKey(
        ScanRun, on_delete=models.CASCADE, related_name="nodes", null=True, blank=True
    )
    ip_address = models.GenericIPAddressField()
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=32, default="online")
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    description = models.TextField(blank=True)
    agent_id = models.CharField(max_length=64, unique=True, null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["agent_id"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.ip_address})"


class NodeInterface(models.Model):
    node = models.ForeignKey(Node, on_delete=models.CASCADE, related_name="interfaces")
    name = models.CharField(max_length=64)
    ip = models.GenericIPAddressField()
    mac = models.CharField(max_length=64)

    class Meta:
        unique_together = ("node", "name")
        indexes = [models.Index(fields=["ip"]), models.Index(fields=["mac"])]

    def __str__(self):
        return f"{self.node.name} - {self.name} ({self.ip})"


class Link(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="links", null=True)
    source = models.ForeignKey(Node, related_name="links_from", on_delete=models.CASCADE)
    destination = models.ForeignKey(Node, related_name="links_to", on_delete=models.CASCADE)
    weight = models.FloatField(validators=[MinValueValidator(0.0)])

    class Meta:
        unique_together = ("scan_run", "source", "destination")
        indexes = [
            models.Index(fields=["scan_run"]),
            models.Index(fields=["source"]),
            models.Index(fields=["destination"]),
        ]

    def __str__(self):
        return f"{self.source} -> {self.destination} (w={self.weight})"


# -----------------------------
# Vulnerabilities
# -----------------------------
class Vulnerability(models.Model):
    """Global CVE catalog entry (deduped by CVE ID)."""
    cve_id = models.CharField(max_length=32, unique=True)
    description = models.TextField()
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, blank=True)
    score = models.FloatField(null=True, blank=True)  # CVSS base score
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    references = models.TextField(blank=True)
    nodes = models.ManyToManyField(Node, blank=True)

    class Meta:
        indexes = [models.Index(fields=["severity"]), models.Index(fields=["last_modified"])]

    def __str__(self):
        sev = self.severity or "Unknown"
        return f"{self.cve_id} ({sev})"


class AgentCommand(models.Model):
    agent_id = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    parameters = models.JSONField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    acknowledged = models.BooleanField(default=False)

    class Meta:
        indexes = [models.Index(fields=["agent_id", "acknowledged", "created"])]

    def __str__(self):
        return f"{self.agent_id} - {self.action}"


class CommandResult(models.Model):
    command = models.ForeignKey(AgentCommand, on_delete=models.CASCADE, related_name="results")
    agent_id = models.CharField(max_length=64)
    output = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["agent_id"]), models.Index(fields=["timestamp"])]

    def __str__(self):
        return f"Result {self.id} for {self.agent_id} @ {self.timestamp:%Y-%m-%d %H:%M:%S}"


class ScanVulnerability(models.Model):
    """
    Per-scan host finding (kept separate from the global Vulnerability catalog).
    """
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="vulnerabilities")
    host_ip = models.GenericIPAddressField()
    cve_id = models.CharField(max_length=32)
    name = models.CharField(max_length=255)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="Medium")
    cvss_score = models.FloatField(null=True, blank=True)
    description = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["host_ip", "cve_id"]),
            models.Index(fields=["scan_run"]),
        ]
        unique_together = ("scan_run", "host_ip", "cve_id")

    def __str__(self):
        return f"{self.cve_id} on {self.host_ip} ({self.severity})"


# -----------------------------
# Local host (agent machine) and its interfaces
# -----------------------------
class Host(models.Model):
    """
    The machine running the local agent/sniffer. Separate from Node to avoid
    conflating local inventory with discovered remote endpoints.
    """
    agent_id = models.CharField(max_length=64, unique=True)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    platform = models.CharField(max_length=64, blank=True)   # e.g., "Linux", "Windows"
    kernel = models.CharField(max_length=128, blank=True)    # e.g., "5.15.0-...-generic"
    arch = models.CharField(max_length=32, blank=True)       # e.g., "x86_64", "aarch64"
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["agent_id"]),
            models.Index(fields=["hostname"]),
        ]

    def __str__(self):
        return f"{self.hostname} ({self.agent_id})"


class LocalNetworkInterface(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="interfaces", null=True, blank=True)

    iface_name = models.CharField(max_length=64)  # e.g., ens33, docker0, br-*, veth*, lo
    kind = models.CharField(
        max_length=20,
        choices=[
            ("ethernet", "Ethernet"),
            ("bridge", "Bridge"),
            ("loopback", "Loopback"),
            ("veth", "Veth"),
            ("docker_bridge", "DockerBridge"),
            ("libvirt_bridge", "LibvirtBridge"),
            ("other", "Other"),
        ],
        default="other",
    )
    mac_address = models.CharField(max_length=17, null=True, blank=True)
    mtu = models.PositiveIntegerField(null=True, blank=True)
    txqueuelen = models.PositiveIntegerField(null=True, blank=True)

    # Flags/oper state
    is_up = models.BooleanField(default=False)
    is_running = models.BooleanField(default=False)
    supports_broadcast = models.BooleanField(default=False)
    supports_multicast = models.BooleanField(default=False)

    # Bridge membership (e.g., enslaved to br-...)
    master = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="slaves")

    managed_by = models.CharField(
        max_length=16,
        choices=[("kernel", "Kernel"), ("docker", "Docker"), ("libvirt", "Libvirt"), ("other", "Other")],
        default="other",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("host", "iface_name")
        indexes = [
            models.Index(fields=["iface_name"]),
            models.Index(fields=["managed_by", "kind"]),
        ]

    def __str__(self):
        h = self.host.hostname if self.host_id else "local"
        return f"{h}:{self.iface_name}"


class InterfaceAddress(models.Model):
    iface = models.ForeignKey(LocalNetworkInterface, on_delete=models.CASCADE, related_name="addresses")
    family = models.CharField(max_length=5, choices=[("ipv4", "IPv4"), ("ipv6", "IPv6")])
    address = models.GenericIPAddressField()
    prefixlen = models.PositiveSmallIntegerField()                   # e.g., 24 or 64
    broadcast = models.GenericIPAddressField(null=True, blank=True)  # IPv4 only
    scope = models.CharField(max_length=16, null=True, blank=True)   # e.g., "link"
    is_primary = models.BooleanField(default=False)
    is_link_local = models.BooleanField(default=False)

    class Meta:
        indexes = [models.Index(fields=["family", "address"])]

    def __str__(self):
        return f"{self.iface}:{self.address}/{self.prefixlen}"


class InterfaceStats(models.Model):
    iface = models.OneToOneField(LocalNetworkInterface, on_delete=models.CASCADE, related_name="stats")

    rx_packets = models.BigIntegerField(default=0)
    rx_bytes = models.BigIntegerField(default=0)
    rx_errors = models.BigIntegerField(default=0)
    rx_dropped = models.BigIntegerField(default=0)
    rx_overruns = models.BigIntegerField(default=0)
    rx_frame = models.BigIntegerField(default=0)

    tx_packets = models.BigIntegerField(default=0)
    tx_bytes = models.BigIntegerField(default=0)
    tx_errors = models.BigIntegerField(default=0)
    tx_dropped = models.BigIntegerField(default=0)
    tx_overruns = models.BigIntegerField(default=0)
    tx_carrier = models.BigIntegerField(default=0)
    tx_collisions = models.BigIntegerField(default=0)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Stats({self.iface})"
