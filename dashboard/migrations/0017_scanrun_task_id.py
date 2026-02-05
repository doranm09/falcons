from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0016_minimega_execution_log"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanrun",
            name="task_id",
            field=models.CharField(blank=True, db_index=True, max_length=64, null=True),
        ),
    ]
