from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0024_hunts"),
    ]

    operations = [
        migrations.CreateModel(
            name="SiemUserRole",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role", models.CharField(choices=[("admin", "Admin"), ("analyst", "Analyst"), ("viewer", "Viewer")], default="viewer", max_length=16)),
                ("assigned_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="siem_role", to=settings.AUTH_USER_MODEL),
                ),
            ],
        ),
        migrations.CreateModel(
            name="SiemAuditLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role", models.CharField(blank=True, max_length=16)),
                ("action", models.CharField(max_length=128)),
                ("resource_type", models.CharField(blank=True, max_length=64)),
                ("resource_id", models.CharField(blank=True, max_length=64)),
                ("status", models.CharField(choices=[("success", "Success"), ("denied", "Denied"), ("error", "Error")], default="success", max_length=16)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=255)),
                ("metadata", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="siemuserrole",
            index=models.Index(fields=["role"], name="dashboard_siemuserrole_role_7b52b8_idx"),
        ),
        migrations.AddIndex(
            model_name="siemauditlog",
            index=models.Index(fields=["action", "status"], name="dashboard_siemaudit_action_12d3d5_idx"),
        ),
        migrations.AddIndex(
            model_name="siemauditlog",
            index=models.Index(fields=["created_at"], name="dashboard_siemaudit_created_5b54e4_idx"),
        ),
    ]
