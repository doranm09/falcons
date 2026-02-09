from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


# -----------------------------
# Teamserver Configuration
# -----------------------------
class Teamserver(models.Model):
    """Sliver C2 teamserver connection configuration."""
    name = models.CharField(max_length=100, unique=True, help_text="Descriptive name for this teamserver")
    host = models.CharField(max_length=255, help_text="Teamserver hostname or IP")
    port = models.PositiveIntegerField(default=31337, help_text="Teamserver port")
    ca_cert = models.TextField(blank=True, help_text="CA certificate for TLS")
    private_key = models.TextField(blank=True, help_text="Private key for client authentication")
    certificate = models.TextField(blank=True, help_text="Client certificate for TLS")

    # Connection status
    is_connected = models.BooleanField(default=False, help_text="Whether teamserver is currently connected")
    last_connected = models.DateTimeField(null=True, blank=True, help_text="Last successful connection time")
    last_error = models.TextField(blank=True, help_text="Last connection error message")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Teamserver"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.host}:{self.port})"


# -----------------------------
# Engagements / Operations
# -----------------------------
class Engagement(models.Model):
    """A Sliver engagement/campaign."""
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        PAUSED = "PAUSED", "Paused"
        COMPLETED = "COMPLETED", "Completed"
        ARCHIVED = "ARCHIVED", "Archived"

    name = models.CharField(max_length=200, unique=True, help_text="Engagement name")
    description = models.TextField(blank=True, help_text="Engagement description")
    teamserver = models.ForeignKey(Teamserver, on_delete=models.CASCADE)

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    tags = models.JSONField(default=list, blank=True, help_text="Tags for organization")

    # Engagement scope and targeting
    target_scope = models.TextField(blank=True, help_text="Target network/IP ranges")
    implant_config = models.JSONField(default=dict, blank=True, help_text="Default implant configuration")

    # Metadata
    operator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Engagement"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.get_status_display()})"

    def get_active_sessions_count(self):
        return self.sliversession_set.filter(status='ACTIVE').count()

    def get_completed_jobs_count(self):
        return SliverJob.objects.filter(session__engagement=self, status='COMPLETED').count()


# -----------------------------
# Implant/Stager Management
# -----------------------------
class ImplantTemplate(models.Model):
    """Reusable implant/stager templates."""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    config = models.JSONField(help_text="Implant generation configuration")
    file_format = models.CharField(max_length=50, default="exe", help_text="Output format (exe, dll, etc.)")

    # Template metadata
    operating_system = models.CharField(max_length=50, default="windows")
    architecture = models.CharField(max_length=20, default="amd64")
    is_default = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Implant Template"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.operating_system}/{self.architecture})"


# -----------------------------
# Generated Implants / Artifacts
# -----------------------------
class ImplantArtifact(models.Model):
    """Generated implant/stager artifacts stored by the dashboard."""
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        READY = "READY", "Ready"
        FAILED = "FAILED", "Failed"

    name = models.CharField(max_length=200, help_text="Logical implant name")
    file_name = models.CharField(max_length=255, blank=True, help_text="Artifact filename")
    relative_path = models.CharField(max_length=500, blank=True, help_text="Relative path under artifact directory")

    engagement = models.ForeignKey(Engagement, on_delete=models.SET_NULL, null=True, blank=True)
    template = models.ForeignKey(ImplantTemplate, on_delete=models.SET_NULL, null=True, blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    file_size = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    download_token = models.CharField(max_length=128, blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Implant Artifact"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.get_status_display()})"

# -----------------------------
# Sessions (Beacons/Interactive)
# -----------------------------
class SliverSession(models.Model):
    """Sliver session (beacon or interactive implant)."""
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        DEAD = "DEAD", "Dead"
        DISCONNECTED = "DISCONNECTED", "Disconnected"

    class Type(models.TextChoices):
        BEACON = "BEACON", "Beacon"
        SESSION = "SESSION", "Interactive Session"

    session_id = models.CharField(max_length=64, unique=True, help_text="Sliver session ID")
    name = models.CharField(max_length=255, blank=True, help_text="Session name")

    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    session_type = models.CharField(max_length=20, choices=Type.choices, default=Type.BEACON)

    # Host information
    hostname = models.CharField(max_length=255, blank=True)
    username = models.CharField(max_length=255, blank=True)
    uid = models.CharField(max_length=64, blank=True)
    gid = models.CharField(max_length=64, blank=True)
    os = models.CharField(max_length=100, blank=True)
    arch = models.CharField(max_length=50, blank=True)
    pid = models.PositiveIntegerField(null=True, blank=True)
    remote_address = models.GenericIPAddressField(null=True, blank=True)
    version = models.CharField(max_length=50, blank=True)

    # Session properties
    is_privileged = models.BooleanField(default=False)
    transport = models.CharField(max_length=50, blank=True, help_text="Communication transport (mtls, wg, http, etc.)")
    encoder = models.CharField(max_length=50, blank=True)
    reconfigure_interval = models.PositiveIntegerField(null=True, blank=True, help_text="Beacon interval in seconds")

    # Timestamps
    first_seen = models.DateTimeField(auto_now_add=True)
    last_checkin = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Sliver Session"
        ordering = ['-last_checkin']

    def __str__(self):
        return f"{self.name or self.session_id} ({self.get_status_display()})"

    def is_online(self):
        """Check if session is currently online."""
        if self.status == self.Status.DEAD:
            return False
        # Consider online if checked in within the last 5 minutes + beacon interval
        threshold = timezone.now() - timezone.timedelta(
            seconds=(self.reconfigure_interval or 60) + 300
        )
        return self.last_checkin > threshold


# -----------------------------
# Job/Attack Templates
# -----------------------------
class TaskTemplate(models.Model):
    """Pre-defined operation templates."""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    command = models.TextField(help_text="Sliver command to execute")
    parameters = models.JSONField(default=dict, blank=True, help_text="Command parameters")

    # Classification
    category = models.CharField(max_length=50, default="general", help_text="recon, persistence, lateral, etc.")
    is_builtin = models.BooleanField(default=False, help_text="Built-in vs custom template")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Task Template"
        ordering = ['category', 'name']

    def __str__(self):
        return f"{self.name} ({self.category})"


# -----------------------------
# Jobs/Tasks
# -----------------------------
class SliverJob(models.Model):
    """Async job/task execution."""
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    job_id = models.CharField(max_length=64, unique=True, help_text="Sliver job ID")
    name = models.CharField(max_length=200, blank=True)

    session = models.ForeignKey(SliverSession, on_delete=models.CASCADE)
    template = models.ForeignKey(TaskTemplate, on_delete=models.SET_NULL, null=True, blank=True)

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    command = models.TextField(help_text="Executed command")
    parameters = models.JSONField(default=dict, blank=True)

    # Results
    output = models.TextField(blank=True, help_text="Command output")
    error = models.TextField(blank=True, help_text="Error message")
    exit_code = models.IntegerField(null=True, blank=True)

    # Timing
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    operator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Sliver Job"
        ordering = ['-created_at']

    def __str__(self):
        return f"Job {self.job_id} ({self.get_status_display()})"

    def duration(self):
        """Calculate job duration."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None


# -----------------------------
# Loot/Results Collection
# -----------------------------
class Loot(models.Model):
    """Collected loot/results from operations."""
    class Type(models.TextChoices):
        FILE = "FILE", "File"
        CREDENTIALS = "CREDENTIALS", "Credentials"
        SYSTEM_INFO = "SYSTEM_INFO", "System Information"
        NETWORK_CONFIG = "NETWORK_CONFIG", "Network Configuration"
        OTHER = "OTHER", "Other"

    loot_id = models.CharField(max_length=64, unique=True, help_text="Sliver loot ID")
    name = models.CharField(max_length=200, blank=True)
    loot_type = models.CharField(max_length=20, choices=Type.choices, default=Type.FILE)

    session = models.ForeignKey(SliverSession, on_delete=models.CASCADE)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE)

    # Loot content
    file_path = models.CharField(max_length=500, blank=True, help_text="Remote file path if applicable")
    local_path = models.FileField(upload_to='sliver_loot/%Y/%m/%d/', null=True, blank=True)
    content = models.TextField(blank=True, help_text="Text content if applicable")
    size_bytes = models.PositiveIntegerField(default=0)

    # Metadata
    collected_at = models.DateTimeField(default=timezone.now)
    operator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Loot"
        verbose_name_plural = "Loot"
        ordering = ['-collected_at']

    def __str__(self):
        return f"{self.name or self.loot_id} ({self.get_loot_type_display()})"


# -----------------------------
# Event Logging
# -----------------------------
class SliverEvent(models.Model):
    """Sliver events for real-time monitoring."""
    class Type(models.TextChoices):
        SESSION_OPENED = "SESSION_OPENED", "Session Opened"
        SESSION_CLOSED = "SESSION_CLOSED", "Session Closed"
        JOB_STARTED = "JOB_STARTED", "Job Started"
        JOB_COMPLETED = "JOB_COMPLETED", "Job Completed"
        LOOT_COLLECTED = "LOOT_COLLECTED", "Loot Collected"
        WATCHER_TRIGGERED = "WATCHER_TRIGGERED", "Watcher Triggered"
        CANARY_TRIGGERED = "CANARY_TRIGGERED", "Canary Triggered"

    event_id = models.CharField(max_length=64, unique=True, help_text="Sliver event ID")
    event_type = models.CharField(max_length=30, choices=Type.choices)

    teamserver = models.ForeignKey(Teamserver, on_delete=models.CASCADE)
    engagement = models.ForeignKey(Engagement, on_delete=models.SET_NULL, null=True, blank=True)
    session = models.ForeignKey(SliverSession, on_delete=models.SET_NULL, null=True, blank=True)

    # Event details
    data = models.JSONField(default=dict, help_text="Event-specific data")
    message = models.TextField(blank=True)

    # Timestamps
    timestamp = models.DateTimeField(default=timezone.now)
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Sliver Event"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.event_type} ({self.timestamp})"


# -----------------------------
# Audit Log
# -----------------------------
class AuditLog(models.Model):
    """Audit trail for all Sliver operations."""
    class Action(models.TextChoices):
        ENGAGEMENT_STARTED = "ENGAGEMENT_STARTED", "Engagement Started"
        ENGAGEMENT_STOPPED = "ENGAGEMENT_STOPPED", "Engagement Stopped"
        IMPLANT_GENERATED = "IMPLANT_GENERATED", "Implant Generated"
        IMPLANT_DEPLOYED = "IMPLANT_DEPLOYED", "Implant Deploy Queued"
        IMPLANT_DELIVERED = "IMPLANT_DELIVERED", "Implant Delivered"
        IMPLANT_EXECUTED = "IMPLANT_EXECUTED", "Implant Executed"
        IMPLANT_DEPLOY_FAILED = "IMPLANT_DEPLOY_FAILED", "Implant Deploy Failed"
        SESSION_CONNECTED = "SESSION_CONNECTED", "Session Connected"
        COMMAND_EXECUTED = "COMMAND_EXECUTED", "Command Executed"
        LOOT_DOWNLOADED = "LOOT_DOWNLOADED", "Loot Downloaded"
        TEAMSERVER_CONNECTED = "TEAMSERVER_CONNECTED", "Teamserver Connected"
        TEAMSERVER_DISCONNECTED = "TEAMSERVER_DISCONNECTED", "Teamserver Disconnected"

    action = models.CharField(max_length=50, choices=Action.choices)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    teamserver = models.ForeignKey(Teamserver, on_delete=models.CASCADE)

    # Related objects (optional)
    engagement = models.ForeignKey(Engagement, on_delete=models.SET_NULL, null=True, blank=True)
    session = models.ForeignKey(SliverSession, on_delete=models.SET_NULL, null=True, blank=True)
    job = models.ForeignKey(SliverJob, on_delete=models.SET_NULL, null=True, blank=True)
    loot = models.ForeignKey(Loot, on_delete=models.SET_NULL, null=True, blank=True)

    # Details
    details = models.JSONField(default=dict, help_text="Action-specific details")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    timestamp = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = "Audit Log"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.get_action_display()} by {self.user or 'System'} ({self.timestamp})"


# -----------------------------
# Monitoring/Watchers
# -----------------------------
class Watcher(models.Model):
    """Event-based watchers for automated responses."""
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE)
    event_filter = models.JSONField(help_text="Event filtering criteria")
    action_config = models.JSONField(help_text="Automated response actions")

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Watcher: {self.name}"
