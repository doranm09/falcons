from django.contrib import admin
from .models import Node

@admin.register(Node)
class NodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'status', 'last_heartbeat')
    search_fields = ('name', 'ip_address')
    list_filter = ('status',)
