from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0023_threat_intel"),
    ]

    operations = [
        migrations.CreateModel(
            name="Hunt",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("description", models.TextField(blank=True)),
                ("status", models.CharField(choices=[("open", "Open"), ("closed", "Closed")], default="open", max_length=16)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
                ),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.CreateModel(
            name="HuntNote",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(blank=True, max_length=255)),
                ("note", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "author",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
                ),
                (
                    "hunt",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="notes", to="dashboard.hunt"),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="HuntSearch",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255)),
                ("query_params", models.JSONField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "hunt",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="searches", to="dashboard.hunt"),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="HuntTag",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "hunt",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tags", to="dashboard.hunt"),
                ),
            ],
            options={
                "ordering": ["name"],
                "unique_together": {("hunt", "name")},
            },
        ),
        migrations.AddIndex(
            model_name="hunt",
            index=models.Index(fields=["status", "updated_at"], name="dashboard_hunt_status_6b133d_idx"),
        ),
    ]
