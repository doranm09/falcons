from django.contrib import admin
from .models import (
    Node,
    Link,
    ScanRun,
    Vulnerability,
    AgentCommand,
    CommandResult,
    NodeInterface,
    AgentStatus,
    ScanVulnerability,
    Host,
    LocalNetworkInterface,
    InterfaceAddress,
    InterfaceStats,
    NetworkMetadata,
    NetworkConnection,
    NetworkFlow,
    SbomReport,
    MinimegaExecutionLog,
    RiskNodeMapping,
    SiemEvent,
    AlertRule,
    Alert,
    Case,
    CaseNote,
    CaseEvidence,
    ThreatIntelIndicator,
    ThreatIntelMatch,
)

@admin.register(Node)
class NodeAdmin(admin.ModelAdmin):
    list_display = ("name", "ip_address", "status", "last_heartbeat")
    search_fields = ("name", "ip_address")
    list_filter = ("status",)


@admin.register(RiskNodeMapping)
class RiskNodeMappingAdmin(admin.ModelAdmin):
    list_display = ("risk_node_id", "node", "ip_address", "active", "updated_at")
    search_fields = ("risk_node_id", "node__name", "node__ip_address", "ip_address", "label")
    list_filter = ("active",)


@admin.register(Link)
class LinkAdmin(admin.ModelAdmin):
    list_display = ("source", "destination", "weight")
    search_fields = ("source__ip_address", "destination__ip_address")


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("cidr", "timestamp", "status", "result_summary")
    readonly_fields = ("timestamp",)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "severity", "score", "published", "last_modified")
    search_fields = ("cve_id", "description", "references")
    list_filter = ("severity", "published")


@admin.register(AgentCommand)
class AgentCommandAdmin(admin.ModelAdmin):
    list_display = ("id", "agent_id", "action", "acknowledged", "created")
    list_filter = ("acknowledged", "action")
    search_fields = ("agent_id", "action")


@admin.register(CommandResult)
class CommandResultAdmin(admin.ModelAdmin):
    list_display = ("id", "agent_id", "command", "timestamp")
    search_fields = ("agent_id", "command__action")


@admin.register(NodeInterface)
class NodeInterfaceAdmin(admin.ModelAdmin):
    list_display = ("node", "name", "ip", "mac")
    search_fields = ("node__name", "ip", "mac")


@admin.register(AgentStatus)
class AgentStatusAdmin(admin.ModelAdmin):
    list_display = ("hostname", "agent_id", "ip_address", "status", "last_heartbeat")
    search_fields = ("agent_id", "hostname", "ip_address")
    list_filter = ("status", "os_type", "platform")


@admin.register(ScanVulnerability)
class ScanVulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("scan_run", "host_ip", "cve_id", "severity", "cvss_score")
    search_fields = ("host_ip", "cve_id", "name")
    list_filter = ("severity", "scan_run")


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("hostname", "agent_id", "ip_address", "platform", "last_heartbeat")
    search_fields = ("agent_id", "hostname", "ip_address")


@admin.register(LocalNetworkInterface)
class LocalNetworkInterfaceAdmin(admin.ModelAdmin):
    list_display = ("host", "iface_name", "kind", "mac_address", "is_up", "is_running")
    search_fields = ("iface_name", "mac_address", "host__hostname")
    list_filter = ("kind", "managed_by", "is_up", "is_running")


@admin.register(InterfaceAddress)
class InterfaceAddressAdmin(admin.ModelAdmin):
    list_display = ("iface", "family", "address", "prefixlen", "scope")
    search_fields = ("address", "iface__iface_name")
    list_filter = ("family", "is_primary", "is_link_local")


@admin.register(InterfaceStats)
class InterfaceStatsAdmin(admin.ModelAdmin):
    list_display = ("iface", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
    search_fields = ("iface__iface_name",)
    readonly_fields = (
        "rx_packets",
        "rx_bytes",
        "rx_errors",
        "rx_dropped",
        "rx_overruns",
        "rx_frame",
        "tx_packets",
        "tx_bytes",
        "tx_errors",
        "tx_dropped",
        "tx_overruns",
        "tx_carrier",
        "tx_collisions",
    )


@admin.register(NetworkMetadata)
class NetworkMetadataAdmin(admin.ModelAdmin):
    list_display = ("agent", "timestamp", "total_connections", "total_interfaces", "collection_duration_ms")
    search_fields = ("agent__hostname", "agent__agent_id")
    list_filter = ("agent", "timestamp")
    readonly_fields = ("timestamp",)


@admin.register(NetworkConnection)
class NetworkConnectionAdmin(admin.ModelAdmin):
    list_display = ("agent", "protocol", "local_address", "local_port", "remote_address", "remote_port", "status")
    search_fields = ("local_address", "remote_address", "process_name", "agent__hostname")
    list_filter = ("protocol", "status", "agent")


@admin.register(NetworkFlow)
class NetworkFlowAdmin(admin.ModelAdmin):
    list_display = ("agent", "source_ip", "source_port", "destination_ip", "destination_port", "protocol")
    search_fields = ("source_ip", "destination_ip", "agent__hostname")
    list_filter = ("protocol", "agent")
    readonly_fields = ("bytes_sent", "bytes_received", "packets_sent", "packets_received", "duration_seconds")


@admin.register(SbomReport)
class SbomReportAdmin(admin.ModelAdmin):
    list_display = ("id", "agent_id", "node", "format", "package_count", "created_at")
    search_fields = ("agent_id", "node__name", "node__ip_address")
    list_filter = ("format",)


@admin.register(MinimegaExecutionLog)
class MinimegaExecutionLogAdmin(admin.ModelAdmin):
    list_display = ("id", "action", "scan", "status", "returncode", "created_at")
    search_fields = ("action", "scan__cidr", "disk_image", "script_path")
    list_filter = ("action", "status")


@admin.register(SiemEvent)
class SiemEventAdmin(admin.ModelAdmin):
    list_display = ("id", "event_type", "source", "timestamp", "severity", "asset_ip")
    search_fields = ("event_type", "source", "summary", "asset_id", "asset_ip")
    list_filter = ("event_type", "source", "severity")
    readonly_fields = ("ingested_at",)


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "rule_type", "enabled", "severity", "suppression_minutes")
    list_filter = ("rule_type", "enabled")
    search_fields = ("name", "description", "match_event_type", "match_source")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("id", "rule_name", "status", "severity", "asset_ip", "last_seen", "count")
    list_filter = ("status", "rule_type")
    search_fields = ("rule_name", "summary", "asset_ip", "asset_id")
    readonly_fields = ("first_seen", "last_seen")


@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "status", "priority", "updated_at")
    list_filter = ("status", "priority")
    search_fields = ("title", "description")
    filter_horizontal = ("alerts",)


@admin.register(CaseNote)
class CaseNoteAdmin(admin.ModelAdmin):
    list_display = ("id", "case", "author", "created_at")
    search_fields = ("note",)


@admin.register(CaseEvidence)
class CaseEvidenceAdmin(admin.ModelAdmin):
    list_display = ("id", "case", "label", "evidence_type", "created_at")
    search_fields = ("label", "details")


@admin.register(ThreatIntelIndicator)
class ThreatIntelIndicatorAdmin(admin.ModelAdmin):
    list_display = ("id", "indicator_type", "value", "source", "active", "updated_at")
    list_filter = ("indicator_type", "active")
    search_fields = ("value", "description", "source")


@admin.register(ThreatIntelMatch)
class ThreatIntelMatchAdmin(admin.ModelAdmin):
    list_display = ("id", "indicator", "event", "matched_field", "created_at")
    list_filter = ("matched_field",)
