# Generated by Django 3.0.7 on 2021-02-03 13:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0029_project_db_pentester'),
    ]

    operations = [
        migrations.AlterField(
            model_name='project_db',
            name='client',
            field=models.TextField(blank=True, null=True),
        ),
    ]
