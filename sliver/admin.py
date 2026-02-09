from django.contrib import admin

from .models import (
    Teamserver,
    Engagement,
    ImplantTemplate,
    ImplantArtifact,
    SliverSession,
    TaskTemplate,
    SliverJob,
    Loot,
    SliverEvent,
    AuditLog,
    Watcher,
)

admin.site.register(Teamserver)
admin.site.register(Engagement)
admin.site.register(ImplantTemplate)
admin.site.register(ImplantArtifact)
admin.site.register(SliverSession)
admin.site.register(TaskTemplate)
admin.site.register(SliverJob)
admin.site.register(Loot)
admin.site.register(SliverEvent)
admin.site.register(AuditLog)
admin.site.register(Watcher)
