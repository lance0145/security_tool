# Generated by Django 3.0.7 on 2021-06-21 23:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tools', '0021_audit_db_audit_question_db'),
    ]

    operations = [
        migrations.AddField(
            model_name='audit_db',
            name='answer_color',
            field=models.TextField(blank=True, null=True),
        ),
    ]