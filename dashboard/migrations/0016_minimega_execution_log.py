from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0015_sbomreport'),
    ]

    operations = [
        migrations.CreateModel(
            name='MinimegaExecutionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(choices=[('execute', 'Execute'), ('reset', 'Reset'), ('kill', 'Kill')], max_length=16)),
                ('disk_image', models.CharField(blank=True, max_length=512)),
                ('vlan', models.CharField(blank=True, max_length=64)),
                ('memory_mb', models.PositiveIntegerField(default=0)),
                ('enable_virtio', models.BooleanField(default=False)),
                ('script_path', models.CharField(blank=True, max_length=512)),
                ('command', models.CharField(blank=True, max_length=512)),
                ('status', models.CharField(default='unknown', max_length=32)),
                ('returncode', models.IntegerField(blank=True, null=True)),
                ('stdout', models.TextField(blank=True)),
                ('stderr', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='dashboard.scanrun')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='minimegaexecutionlog',
            index=models.Index(fields=['action', 'created_at'], name='dashboard_m_action__b6f4b2_idx'),
        ),
        migrations.AddIndex(
            model_name='minimegaexecutionlog',
            index=models.Index(fields=['scan'], name='dashboard_m_scan_6d7207_idx'),
        ),
    ]
