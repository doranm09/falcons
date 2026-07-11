from django.db import migrations, models


def backfill_node_hostname(apps, schema_editor):
    Node = apps.get_model("dashboard", "Node")
    AgentStatus = apps.get_model("dashboard", "AgentStatus")

    agent_hostname_by_id = {
        str(agent_id): str(hostname or "").strip()
        for agent_id, hostname in AgentStatus.objects.exclude(hostname="").values_list("agent_id", "hostname")
    }

    for node in Node.objects.all().iterator():
        hostname = ""
        if node.agent_id:
            hostname = agent_hostname_by_id.get(str(node.agent_id), "")
        if not hostname:
            candidate = str(node.name or "").strip()
            ip_text = str(node.ip_address or "").strip()
            if candidate and candidate != ip_text:
                hostname = candidate
        if hostname:
            Node.objects.filter(pk=node.pk).update(hostname=hostname)


def clear_node_hostname(apps, schema_editor):
    Node = apps.get_model("dashboard", "Node")
    Node.objects.all().update(hostname="")


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0029_sbomreport_scan_metadata"),
    ]

    operations = [
        migrations.AddField(
            model_name="node",
            name="hostname",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.RunPython(backfill_node_hostname, clear_node_hostname),
    ]
