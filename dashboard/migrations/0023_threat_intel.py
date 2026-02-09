from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0022_cases"),
    ]

    operations = [
        migrations.CreateModel(
            name="ThreatIntelIndicator",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("value", models.CharField(db_index=True, max_length=512)),
                ("indicator_type", models.CharField(choices=[("ip", "IP"), ("domain", "Domain"), ("url", "URL"), ("hash", "Hash")], max_length=16)),
                ("source", models.CharField(blank=True, max_length=128)),
                ("description", models.TextField(blank=True)),
                ("confidence", models.IntegerField(blank=True, null=True)),
                ("tlp", models.CharField(blank=True, max_length=16)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["indicator_type", "active"], name="dashboard_thr_indica_1c1a3a_idx"),
                    models.Index(fields=["source"], name="dashboard_thr_source_d3e7b6_idx"),
                ],
                "unique_together": {("indicator_type", "value")},
            },
        ),
        migrations.CreateModel(
            name="ThreatIntelMatch",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("matched_field", models.CharField(max_length=64)),
                ("matched_value", models.CharField(max_length=512)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("event", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="ioc_matches", to="dashboard.siemevent")),
                ("indicator", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="dashboard.threatintelindicator")),
            ],
            options={
                "indexes": [
                    models.Index(fields=["matched_field"], name="dashboard_thr_matche_5df1d0_idx"),
                    models.Index(fields=["created_at"], name="dashboard_thr_created_9c5f87_idx"),
                ],
                "unique_together": {("indicator", "event", "matched_field")},
            },
        ),
    ]
