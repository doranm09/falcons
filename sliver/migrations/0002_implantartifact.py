from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sliver', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ImplantArtifact',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Logical implant name', max_length=200)),
                ('file_name', models.CharField(blank=True, help_text='Artifact filename', max_length=255)),
                ('relative_path', models.CharField(blank=True, help_text='Relative path under artifact directory', max_length=500)),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('RUNNING', 'Running'), ('READY', 'Ready'), ('FAILED', 'Failed')], default='PENDING', max_length=20)),
                ('file_size', models.PositiveBigIntegerField(default=0)),
                ('sha256', models.CharField(blank=True, max_length=64)),
                ('error_message', models.TextField(blank=True)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('engagement', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='sliver.engagement')),
                ('generated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='auth.user')),
                ('template', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='sliver.implanttemplate')),
            ],
            options={
                'verbose_name': 'Implant Artifact',
                'ordering': ['-created_at'],
            },
        ),
    ]

