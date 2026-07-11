from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0031_siem_sensor_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="siemevent",
            name="destination_ip",
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="siemevent",
            name="event_dataset",
            field=models.CharField(blank=True, db_index=True, max_length=150),
        ),
        migrations.AddField(
            model_name="siemevent",
            name="event_module",
            field=models.CharField(blank=True, db_index=True, max_length=100),
        ),
        migrations.AddField(
            model_name="siemevent",
            name="network_community_id",
            field=models.CharField(blank=True, db_index=True, max_length=128),
        ),
        migrations.AddField(
            model_name="siemevent",
            name="observer_name",
            field=models.CharField(blank=True, db_index=True, max_length=255),
        ),
        migrations.AddField(
            model_name="siemevent",
            name="source_ip",
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AddIndex(
            model_name="siemevent",
            index=models.Index(fields=["event_module", "event_dataset"], name="dashboard_s_event_m_7236dc_idx"),
        ),
        migrations.AddIndex(
            model_name="siemevent",
            index=models.Index(fields=["network_community_id"], name="dashboard_s_network_f4be4d_idx"),
        ),
    ]
