from django.db import migrations


def create_default_rules(apps, schema_editor):
    AlertRule = apps.get_model("dashboard", "AlertRule")
    AlertRule.objects.get_or_create(
        name="Suricata Alerts",
        defaults={
            "rule_type": "suricata",
            "enabled": True,
            "match_event_type": "suricata.alert",
            "match_source": "suricata",
            "match_contains": "",
            "suppression_minutes": 5,
            "severity": 5,
            "description": "Default rule for Suricata alerts",
        },
    )


def reverse_default_rules(apps, schema_editor):
    AlertRule = apps.get_model("dashboard", "AlertRule")
    AlertRule.objects.filter(name="Suricata Alerts").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0020_alerting"),
    ]

    operations = [
        migrations.RunPython(create_default_rules, reverse_default_rules),
    ]
