from django.contrib import admin
from .models import Node, Link, ScanRun, Vulnerability, AgentCommand, CommandResult, NodeInterface

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
