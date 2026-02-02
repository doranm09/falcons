from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sliver', '0002_implantartifact'),
    ]

    operations = [
        migrations.AddField(
            model_name='implantartifact',
            name='download_token',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name='implantartifact',
            name='token_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

