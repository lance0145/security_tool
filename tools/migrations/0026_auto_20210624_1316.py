# Generated by Django 3.0.7 on 2021-06-24 13:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tools', '0025_audit_db_question_group_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='audit_answer_db',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('answer_id', models.TextField(blank=True, null=True)),
                ('answer', models.TextField(blank=True, null=True)),
                ('date_time', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.RenameField(
            model_name='audit_db',
            old_name='answer',
            new_name='answer_id',
        ),
    ]
