from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0028_vulnerability_context_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="sbomreport",
            name="scan_metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
