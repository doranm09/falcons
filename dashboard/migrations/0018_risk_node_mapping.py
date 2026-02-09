from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0017_scanrun_task_id"),
    ]

    operations = [
        migrations.CreateModel(
            name="RiskNodeMapping",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("risk_node_id", models.CharField(max_length=255, unique=True)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("label", models.CharField(blank=True, max_length=255)),
                ("notes", models.TextField(blank=True)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("node", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="risk_mappings", to="dashboard.node")),
            ],
            options={
                "indexes": [
                    models.Index(fields=["risk_node_id"], name="dashboard_risk_risk_no_1c34d2_idx"),
                    models.Index(fields=["ip_address"], name="dashboard_risk_ip_add_2f7b3f_idx"),
                    models.Index(fields=["active"], name="dashboard_risk_active_b497a0_idx"),
                ],
            },
        ),
    ]
