from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0014_agentstatus_processes'),
    ]

    operations = [
        migrations.CreateModel(
            name='SbomReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('agent_id', models.CharField(db_index=True, max_length=64)),
                ('format', models.CharField(default='raw', max_length=32)),
                ('bom_format', models.CharField(blank=True, max_length=64)),
                ('spec_version', models.CharField(blank=True, max_length=32)),
                ('document', models.JSONField()),
                ('package_count', models.PositiveIntegerField(default=0)),
                ('os_summary', models.CharField(blank=True, max_length=255)),
                ('sha256', models.CharField(blank=True, max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('node', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sbom_reports', to='dashboard.node')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='sbomreport',
            index=models.Index(fields=['agent_id', 'created_at'], name='dashboard_s_agent_i_0e8a10_idx'),
        ),
        migrations.AddIndex(
            model_name='sbomreport',
            index=models.Index(fields=['sha256'], name='dashboard_s_sha256_8ce239_idx'),
        ),
    ]
