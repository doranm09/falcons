from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0018_risk_node_mapping"),
    ]

    operations = [
        migrations.CreateModel(
            name="SiemEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField(db_index=True)),
                ("ingested_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("source", models.CharField(db_index=True, max_length=100)),
                ("event_type", models.CharField(db_index=True, max_length=120)),
                ("severity", models.IntegerField(blank=True, db_index=True, null=True)),
                ("asset_id", models.CharField(blank=True, db_index=True, max_length=128, null=True)),
                ("asset_ip", models.GenericIPAddressField(blank=True, db_index=True, null=True)),
                ("summary", models.CharField(blank=True, max_length=512)),
                ("raw", models.JSONField()),
            ],
            options={
                "ordering": ["-timestamp"],
                "indexes": [
                    models.Index(fields=["timestamp", "event_type"], name="dashboard_siem_ts_type_idx"),
                    models.Index(fields=["source", "timestamp"], name="dashboard_siem_source_ts_idx"),
                ],
            },
        ),
    ]
