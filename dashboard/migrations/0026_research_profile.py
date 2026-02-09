from django.db import migrations, models


def create_default_research_profile(apps, schema_editor):
    ResearchProfile = apps.get_model("dashboard", "ResearchProfile")
    if not ResearchProfile.objects.filter(name="Research Mode").exists():
        ResearchProfile.objects.create(
            name="Research Mode",
            version="1.0",
            pipeline_version="1.0",
            ruleset_version="1.0",
            retention_days=30,
            max_batch=100,
            active=False,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0025_siem_rbac_audit"),
    ]

    operations = [
        migrations.CreateModel(
            name="ResearchProfile",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("version", models.CharField(max_length=64)),
                ("pipeline_version", models.CharField(blank=True, max_length=64)),
                ("ruleset_version", models.CharField(blank=True, max_length=64)),
                ("retention_days", models.PositiveIntegerField(default=30)),
                ("max_batch", models.PositiveIntegerField(default=500)),
                ("active", models.BooleanField(default=False)),
                ("config", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.AddIndex(
            model_name="researchprofile",
            index=models.Index(fields=["active"], name="dashboard_researchprofile_active_3b7c0d_idx"),
        ),
        migrations.RunPython(create_default_research_profile, reverse_code=migrations.RunPython.noop),
    ]
