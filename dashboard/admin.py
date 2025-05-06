from django.contrib import admin
from .models import Node, Link, ScanRun

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