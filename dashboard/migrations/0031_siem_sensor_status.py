from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0030_node_hostname"),
    ]

    operations = [
        migrations.CreateModel(
            name="SiemSensorStatus",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("sensor_id", models.CharField(max_length=128, unique=True)),
                ("sensor_type", models.CharField(db_index=True, max_length=32)),
                ("hostname", models.CharField(blank=True, max_length=255)),
                ("status", models.CharField(db_index=True, default="online", max_length=16)),
                ("last_seen", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("event_count", models.PositiveIntegerField(default=0)),
                ("interface_names", models.JSONField(blank=True, default=list)),
                ("last_error", models.CharField(blank=True, max_length=255)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["sensor_type", "sensor_id"],
            },
        ),
        migrations.AddIndex(
            model_name="siemsensorstatus",
            index=models.Index(fields=["sensor_type", "status"], name="dashboard_s_sensor__4eb2e8_idx"),
        ),
        migrations.AddIndex(
            model_name="siemsensorstatus",
            index=models.Index(fields=["last_seen"], name="dashboard_s_last_se_f490bb_idx"),
        ),
    ]
