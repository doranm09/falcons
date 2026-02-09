from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0019_siem_event"),
    ]

    operations = [
        migrations.CreateModel(
            name="AlertRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("description", models.TextField(blank=True)),
                ("rule_type", models.CharField(choices=[("sigma", "Sigma"), ("suricata", "Suricata")], default="sigma", max_length=32)),
                ("enabled", models.BooleanField(default=True)),
                ("severity", models.IntegerField(blank=True, null=True)),
                ("match_event_type", models.CharField(blank=True, max_length=120)),
                ("match_source", models.CharField(blank=True, max_length=120)),
                ("match_contains", models.CharField(blank=True, max_length=255)),
                ("suppression_minutes", models.PositiveIntegerField(default=10)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["rule_type", "enabled"], name="dashboard_aler_rule_ty_7a1a1c_idx"),
                    models.Index(fields=["match_event_type"], name="dashboard_aler_match_e_6a8e7f_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="Alert",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("rule_name", models.CharField(max_length=255)),
                ("rule_type", models.CharField(blank=True, max_length=32)),
                ("event_type", models.CharField(blank=True, max_length=120)),
                ("source", models.CharField(blank=True, max_length=120)),
                ("severity", models.IntegerField(blank=True, null=True)),
                ("asset_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("asset_id", models.CharField(blank=True, max_length=128, null=True)),
                ("summary", models.CharField(blank=True, max_length=512)),
                ("status", models.CharField(choices=[("open", "Open"), ("closed", "Closed")], default="open", max_length=16)),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                ("count", models.PositiveIntegerField(default=1)),
                ("dedup_key", models.CharField(db_index=True, max_length=255)),
                ("raw_sample", models.JSONField(blank=True, null=True)),
                ("rule", models.ForeignKey(blank=True, null=True, on_delete=models.SET_NULL, to="dashboard.alertrule")),
            ],
            options={
                "ordering": ["-last_seen"],
                "indexes": [
                    models.Index(fields=["status", "last_seen"], name="dashboard_aler_status_6c0a8c_idx"),
                    models.Index(fields=["rule_type", "event_type"], name="dashboard_aler_rule_ty_3d4be8_idx"),
                ],
            },
        ),
    ]
