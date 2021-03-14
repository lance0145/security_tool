# Generated by Django 3.0.7 on 2021-03-14 23:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('networkscanners', '0018_openvas_scan_db_high_total'),
    ]

    operations = [
        migrations.AddField(
            model_name='openvas_scan_db',
            name='low_total',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='openvas_scan_db',
            name='medium_total',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
