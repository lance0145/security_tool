# Generated by Django 3.0.7 on 2021-06-22 10:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tools', '0023_auto_20210622_0854'),
    ]

    operations = [
        migrations.AddField(
            model_name='audit_db',
            name='date_time',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='audit_question_db',
            name='date_time',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='audit_question_group_db',
            name='date_time',
            field=models.TextField(blank=True, null=True),
        ),
    ]
