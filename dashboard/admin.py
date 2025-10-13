from django.contrib import admin
from .models import (
    Node, Link, ScanRun, Vulnerability, AgentCommand, CommandResult, NodeInterface,
    AgentStatus, ScanVulnerability, Host, LocalNetworkInterface, InterfaceAddress,
    InterfaceStats, NetworkMetadata, NetworkConnection, NetworkFlow
)

@admin.register(Node)
class NodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'status', 'last_heartbeat')
    search_fields = ('name', 'ip_address')
    list_filter = ('status',)


@admin.register(Link)
class LinkAdmin(admin.ModelAdmin):
    list_display = ('source', 'destination', 'weight')
    search_fields = ('source__ip_address', 'destination__ip_address')

@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ('cidr', 'timestamp', 'status', 'result_summary')
    readonly_fields = ('timestamp',)

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
    readonly_fields = ("rx_packets", "rx_bytes", "rx_errors", "rx_dropped", "rx_overruns", "rx_frame",
                      "tx_packets", "tx_bytes", "tx_errors", "tx_dropped", "tx_overruns", "tx_carrier", "tx_collisions")


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
