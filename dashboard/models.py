from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator
from django.conf import settings

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
    ("nmap", "Nmap"),
    ("agent", "Agent"),
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
    task_id = models.CharField(max_length=64, null=True, blank=True, db_index=True)
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


class MinimegaExecutionLog(models.Model):
    class Action(models.TextChoices):
        EXECUTE = "execute", "Execute"
        RESET = "reset", "Reset"
        KILL = "kill", "Kill"

    action = models.CharField(max_length=16, choices=Action.choices)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    scan = models.ForeignKey(ScanRun, null=True, blank=True, on_delete=models.SET_NULL)
    disk_image = models.CharField(max_length=512, blank=True)
    vlan = models.CharField(max_length=64, blank=True)
    memory_mb = models.PositiveIntegerField(default=0)
    enable_virtio = models.BooleanField(default=False)
    script_path = models.CharField(max_length=512, blank=True)
    command = models.CharField(max_length=512, blank=True)
    status = models.CharField(max_length=32, default="unknown")
    returncode = models.IntegerField(null=True, blank=True)
    stdout = models.TextField(blank=True)
    stderr = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["action", "created_at"]),
            models.Index(fields=["scan"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.action} @ {self.created_at:%Y-%m-%d %H:%M:%S}"


class SiemEvent(models.Model):
    timestamp = models.DateTimeField(db_index=True)
    ingested_at = models.DateTimeField(auto_now_add=True, db_index=True)
    source = models.CharField(max_length=100, db_index=True)
    event_type = models.CharField(max_length=120, db_index=True)
    severity = models.IntegerField(null=True, blank=True, db_index=True)
    asset_id = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    asset_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    summary = models.CharField(max_length=512, blank=True)
    raw = models.JSONField()

    class Meta:
        indexes = [
            models.Index(fields=["timestamp", "event_type"]),
            models.Index(fields=["source", "timestamp"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.event_type} @ {self.timestamp:%Y-%m-%d %H:%M:%S}"


class AlertRule(models.Model):
    class RuleType(models.TextChoices):
        SIGMA = "sigma", "Sigma"
        SURICATA = "suricata", "Suricata"

    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    rule_type = models.CharField(max_length=32, choices=RuleType.choices, default=RuleType.SIGMA)
    enabled = models.BooleanField(default=True)
    severity = models.IntegerField(null=True, blank=True)
    match_event_type = models.CharField(max_length=120, blank=True)
    match_source = models.CharField(max_length=120, blank=True)
    match_contains = models.CharField(max_length=255, blank=True)
    suppression_minutes = models.PositiveIntegerField(default=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["rule_type", "enabled"]),
            models.Index(fields=["match_event_type"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.rule_type})"


class Alert(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        CLOSED = "closed", "Closed"

    rule = models.ForeignKey(AlertRule, null=True, blank=True, on_delete=models.SET_NULL)
    rule_name = models.CharField(max_length=255)
    rule_type = models.CharField(max_length=32, blank=True)
    event_type = models.CharField(max_length=120, blank=True)
    source = models.CharField(max_length=120, blank=True)
    severity = models.IntegerField(null=True, blank=True)
    asset_ip = models.GenericIPAddressField(null=True, blank=True)
    asset_id = models.CharField(max_length=128, null=True, blank=True)
    summary = models.CharField(max_length=512, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    count = models.PositiveIntegerField(default=1)
    dedup_key = models.CharField(max_length=255, db_index=True)
    raw_sample = models.JSONField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "last_seen"]),
            models.Index(fields=["rule_type", "event_type"]),
        ]
        ordering = ["-last_seen"]

    def __str__(self):
        return f"{self.rule_name} ({self.status})"


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

    # Cyber template data fields
    os_info = models.TextField(blank=True, null=True, help_text="Operating system information")
    installed_libraries = models.JSONField(blank=True, null=True, help_text="List of installed libraries/packages")
    mac_addresses = models.JSONField(blank=True, null=True, help_text="MAC addresses of network interfaces")
    active_ports = models.JSONField(blank=True, null=True, help_text="Active network ports")

    # Additional system information
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    memory_total = models.BigIntegerField(null=True, blank=True)  # in bytes
    platform_info = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["agent_id"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

    def get_cyber_template_data(self):
        """Get cyber template data in the format expected by the frontend."""
        return {
            "OS": self.os_info or "Unknown",
            "lib": self.installed_libraries or [],
            "MAC": self.mac_addresses or [],
            "port": self.active_ports or []
        }

    def update_cyber_data(self, cyber_data):
        """Update node with cyber template data from agent."""
        self.os_info = cyber_data.get("OS")
        self.installed_libraries = cyber_data.get("lib", [])
        self.mac_addresses = cyber_data.get("MAC", [])
        self.active_ports = cyber_data.get("port", [])
        self.save(update_fields=["os_info", "installed_libraries", "mac_addresses", "active_ports"])


class RiskNodeMapping(models.Model):
    """Mapping between risk model node IDs and discovered network nodes."""
    risk_node_id = models.CharField(max_length=255, unique=True)
    node = models.ForeignKey(Node, null=True, blank=True, on_delete=models.SET_NULL, related_name="risk_mappings")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    label = models.CharField(max_length=255, blank=True)
    notes = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["risk_node_id"]),
            models.Index(fields=["ip_address"]),
            models.Index(fields=["active"]),
        ]

    def __str__(self):
        return f"{self.risk_node_id} -> {self.node or self.ip_address or 'unmapped'}"


class SbomReport(models.Model):
    node = models.ForeignKey(Node, on_delete=models.SET_NULL, null=True, blank=True, related_name="sbom_reports")
    agent_id = models.CharField(max_length=64, db_index=True)
    format = models.CharField(max_length=32, default="raw")
    bom_format = models.CharField(max_length=64, blank=True)
    spec_version = models.CharField(max_length=32, blank=True)
    document = models.JSONField()
    package_count = models.PositiveIntegerField(default=0)
    os_summary = models.CharField(max_length=255, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["agent_id", "created_at"]),
            models.Index(fields=["sha256"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"SBOM {self.agent_id} ({self.package_count} packages)"


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


# -----------------------------
# Enhanced Agent Monitoring
# -----------------------------
class AgentStatus(models.Model):
    """Enhanced agent monitoring with detailed status tracking."""
    agent_id = models.CharField(max_length=64, unique=True)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=32, choices=[
        ("online", "Online"),
        ("offline", "Offline"),
        ("unknown", "Unknown"),
        ("error", "Error")
    ], default="unknown")

    # System information
    os_type = models.CharField(max_length=64, blank=True)
    os_version = models.CharField(max_length=128, blank=True)
    platform = models.CharField(max_length=128, blank=True)
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    memory_total = models.BigIntegerField(null=True, blank=True)  # in bytes

    # Network information
    interfaces = models.JSONField(blank=True, null=True)  # Store interface details
    active_ports = models.JSONField(blank=True, null=True)  # Store active ports

    # Process information
    processes = models.JSONField(blank=True, null=True)  # Store running processes

    # Timing
    first_seen = models.DateTimeField(auto_now_add=True)
    last_heartbeat = models.DateTimeField(auto_now=True)
    last_command_sent = models.DateTimeField(null=True, blank=True)
    last_command_result = models.DateTimeField(null=True, blank=True)

    # Health metrics
    heartbeat_interval = models.PositiveIntegerField(default=30)  # seconds
    response_time_ms = models.FloatField(null=True, blank=True)
    consecutive_failures = models.PositiveIntegerField(default=0)

    # Capabilities
    capabilities = models.JSONField(blank=True, null=True)  # Store agent capabilities

    # Version information
    agent_version = models.CharField(max_length=32, blank=True, null=True)
    last_version_check = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["agent_id"]),
            models.Index(fields=["status"]),
            models.Index(fields=["last_heartbeat"]),
            models.Index(fields=["hostname"]),
        ]
        ordering = ["-last_heartbeat"]

    def __str__(self):
        return f"{self.hostname} ({self.agent_id}) - {self.status}"

    def is_online(self):
        """Check if agent is considered online based on heartbeat timing."""
        if self.status == "offline":
            return False
        from django.utils import timezone
        threshold = self.heartbeat_interval * 3  # 3x heartbeat interval
        return (timezone.now() - self.last_heartbeat).seconds < threshold

    def update_status(self):
        """Update status based on heartbeat timing."""
        if self.is_online():
            if self.status != "online":
                self.status = "online"
                self.consecutive_failures = 0
        else:
            self.status = "offline"
            self.consecutive_failures += 1
        self.save(update_fields=["status", "consecutive_failures"])

    def record_heartbeat(self, data=None):
        """Record a heartbeat with optional system data."""
        from django.utils import timezone
        now = timezone.now()

        # Update basic info if provided
        if data:
            self.hostname = data.get("hostname", self.hostname)
            self.os_type = data.get("os", self.os_type)
            self.os_version = data.get("os_version", self.os_version)
            self.platform = data.get("platform", self.platform)
            self.cpu_count = data.get("cpu_count", self.cpu_count)
            self.memory_total = data.get("memory_total", self.memory_total)
            self.interfaces = data.get("interfaces", self.interfaces)

        self.last_heartbeat = now
        self.status = "online"
        self.consecutive_failures = 0
        self.save()

    def get_uptime(self):
        """Get agent uptime since first seen."""
        if self.first_seen:
            from django.utils import timezone
            return timezone.now() - self.first_seen
        return None


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


# -----------------------------
# Network Metadata and Monitoring (Security Onion-like)
# -----------------------------
class NetworkMetadata(models.Model):
    """Store detailed network metadata from agents similar to Security Onion."""
    agent = models.ForeignKey(AgentStatus, on_delete=models.CASCADE, related_name="network_metadata")
    timestamp = models.DateTimeField(auto_now_add=True)

    # Network connections data
    network_connections = models.JSONField(blank=True, null=True, help_text="Detailed network connections with process info")
    interface_statistics = models.JSONField(blank=True, null=True, help_text="Interface traffic statistics")
    active_ports = models.JSONField(blank=True, null=True, help_text="Active ports and their status")
    interfaces = models.JSONField(blank=True, null=True, help_text="Network interface information")

    # Metadata about the collection
    collection_duration_ms = models.FloatField(null=True, blank=True, help_text="Time taken to collect metadata")
    total_connections = models.PositiveIntegerField(default=0, help_text="Total number of connections found")
    total_interfaces = models.PositiveIntegerField(default=0, help_text="Total number of interfaces found")

    class Meta:
        indexes = [
            models.Index(fields=["agent", "timestamp"]),
            models.Index(fields=["timestamp"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self):
        return f"Network metadata for {self.agent.hostname} at {self.timestamp}"


class NetworkConnection(models.Model):
    """Individual network connection records for detailed analysis."""
    metadata = models.ForeignKey(NetworkMetadata, on_delete=models.CASCADE, related_name="connections")
    agent = models.ForeignKey(AgentStatus, on_delete=models.CASCADE, related_name="connections")

    # Connection details
    protocol = models.CharField(max_length=10, help_text="TCP or UDP")
    local_address = models.CharField(max_length=255, null=True, blank=True)
    local_port = models.PositiveIntegerField(null=True, blank=True)
    remote_address = models.CharField(max_length=255, null=True, blank=True)
    remote_port = models.PositiveIntegerField(null=True, blank=True)
    status = models.CharField(max_length=32, help_text="Connection status (LISTEN, ESTABLISHED, etc.)")

    # Process information
    process_pid = models.PositiveIntegerField(null=True, blank=True)
    process_name = models.CharField(max_length=255, blank=True)
    process_username = models.CharField(max_length=255, blank=True)
    process_cmdline = models.TextField(blank=True)

    # Timing
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["agent", "protocol"]),
            models.Index(fields=["local_address", "local_port"]),
            models.Index(fields=["remote_address", "remote_port"]),
            models.Index(fields=["process_name"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"{self.protocol} {self.local_address}:{self.local_port} -> {self.remote_address}:{self.remote_port}"


class NetworkFlow(models.Model):
    """Aggregated network flow data for traffic analysis."""
    agent = models.ForeignKey(AgentStatus, on_delete=models.CASCADE, related_name="flows")

    # Flow identification
    source_ip = models.GenericIPAddressField()
    source_port = models.PositiveIntegerField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField()
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10)

    # Flow statistics
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)
    packets_sent = models.BigIntegerField(default=0)
    packets_received = models.BigIntegerField(default=0)

    # Timing
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    duration_seconds = models.PositiveIntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=["agent", "protocol"]),
            models.Index(fields=["source_ip", "destination_ip", "protocol"]),
            models.Index(fields=["first_seen"]),
        ]
        unique_together = ["agent", "source_ip", "source_port", "destination_ip", "destination_port", "protocol"]

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.protocol})"
