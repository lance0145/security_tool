# Generated by Django 3.0.7 on 2021-01-31 13:07

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0026_auto_20210131_1301'),
    ]

    operations = [
        migrations.AlterField(
            model_name='project_db',
            name='client',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='projects.client_db'),
        ),
    ]
