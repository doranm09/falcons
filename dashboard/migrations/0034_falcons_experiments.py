import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("dashboard", "0033_siem_event_network_ports"),
    ]

    operations = [
        migrations.CreateModel(
            name="ExperimentSuite",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("suite_id", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("status", models.CharField(choices=[("PENDING", "Pending"), ("RUNNING", "Running"), ("COMPLETED", "Completed"), ("FAILED", "Failed"), ("ROLLBACK_FAILED", "Rollback failed")], db_index=True, default="PENDING", max_length=32)),
                ("manifest", models.JSONField(default=dict)),
                ("locked_manifest", models.JSONField(default=dict)),
                ("manifest_sha256", models.CharField(blank=True, max_length=64)),
                ("model_sha256", models.CharField(blank=True, max_length=64)),
                ("repository_revisions", models.JSONField(blank=True, default=dict)),
                ("environment", models.JSONField(blank=True, default=dict)),
                ("output_dir", models.CharField(blank=True, max_length=1024)),
                ("celery_task_id", models.CharField(blank=True, db_index=True, max_length=64)),
                ("requested_scenarios", models.JSONField(blank=True, default=list)),
                ("repetitions", models.PositiveSmallIntegerField(default=5)),
                ("random_seed", models.PositiveIntegerField(default=20260710)),
                ("error", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("requested_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="falcons_experiment_suites", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.CreateModel(
            name="ScenarioRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("scenario_id", models.CharField(db_index=True, max_length=8)),
                ("condition", models.CharField(default="default", max_length=64)),
                ("repetition", models.PositiveSmallIntegerField(default=1)),
                ("seed", models.PositiveIntegerField(default=0)),
                ("status", models.CharField(choices=[("PENDING", "Pending"), ("RUNNING", "Running"), ("COMPLETED", "Completed"), ("FAILED", "Failed"), ("ROLLED_BACK", "Rolled back"), ("ROLLBACK_FAILED", "Rollback failed")], db_index=True, default="PENDING", max_length=32)),
                ("risk_experiment_id", models.CharField(blank=True, max_length=64)),
                ("risk_evaluation_id", models.CharField(blank=True, max_length=64)),
                ("input_sha256", models.CharField(blank=True, max_length=64)),
                ("output_sha256", models.CharField(blank=True, max_length=64)),
                ("expected_risk", models.FloatField(blank=True, null=True)),
                ("metrics", models.JSONField(blank=True, default=dict)),
                ("result_payload", models.JSONField(blank=True, default=dict)),
                ("rollback_verified", models.BooleanField(default=False)),
                ("error", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("suite", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="scenario_runs", to="dashboard.experimentsuite")),
            ],
            options={"ordering": ["scenario_id", "repetition", "condition"]},
        ),
        migrations.CreateModel(
            name="ExperimentArtifact",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(db_index=True, max_length=64)),
                ("relative_path", models.CharField(max_length=1024)),
                ("sha256", models.CharField(max_length=64)),
                ("size_bytes", models.PositiveBigIntegerField(default=0)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("scenario_run", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="artifacts", to="dashboard.scenariorun")),
                ("suite", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="artifacts", to="dashboard.experimentsuite")),
            ],
            options={"ordering": ["relative_path"]},
        ),
        migrations.AddIndex(model_name="experimentsuite", index=models.Index(fields=["status", "started_at"], name="dashboard_e_status_772999_idx")),
        migrations.AddIndex(model_name="scenariorun", index=models.Index(fields=["suite", "scenario_id"], name="dashboard_s_suite_i_50c42b_idx")),
        migrations.AddIndex(model_name="scenariorun", index=models.Index(fields=["status", "started_at"], name="dashboard_s_status_4c276c_idx")),
        migrations.AddIndex(model_name="experimentartifact", index=models.Index(fields=["suite", "kind"], name="dashboard_e_suite_i_98868e_idx")),
        migrations.AddConstraint(model_name="scenariorun", constraint=models.UniqueConstraint(fields=("suite", "scenario_id", "repetition", "condition"), name="unique_falcons_scenario_condition")),
        migrations.AddConstraint(model_name="experimentartifact", constraint=models.UniqueConstraint(fields=("suite", "relative_path"), name="unique_falcons_suite_artifact_path")),
    ]
