from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0032_siem_event_network_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="siemevent",
            name="destination_port",
            field=models.PositiveIntegerField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="siemevent",
            name="source_port",
            field=models.PositiveIntegerField(blank=True, db_index=True, null=True),
        ),
    ]
