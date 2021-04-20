# Generated by Django 3.0.7 on 2021-04-20 12:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tools', '0010_auto_20210309_1120'),
    ]

    operations = [
        migrations.CreateModel(
            name='sniper_config_db',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('config_id', models.TextField(blank=True, null=True)),
                ('config_name', models.TextField(blank=True, null=True)),
                ('ip_address', models.TextField(blank=True, null=True)),
                ('script', models.TextField(blank=True, null=True)),
                ('option1', models.TextField(blank=True, null=True)),
                ('option2', models.TextField(blank=True, null=True)),
                ('log1', models.TextField(blank=True, null=True)),
                ('log2', models.TextField(blank=True, null=True)),
                ('result1', models.TextField(blank=True, null=True)),
                ('result', models.TextField(blank=True, null=True)),
                ('username', models.CharField(max_length=256, null=True)),
                ('date_time', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='sniper_result_db',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_id', models.TextField(blank=True, null=True)),
                ('project_id', models.TextField(blank=True, null=True)),
                ('date_time', models.TextField(blank=True, null=True)),
                ('url', models.TextField(blank=True, null=True)),
                ('ip_address', models.TextField(blank=True, null=True)),
                ('status', models.TextField(blank=True, null=True)),
                ('size', models.TextField(blank=True, null=True)),
                ('redirection', models.TextField(blank=True, null=True)),
                ('username', models.CharField(max_length=256, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='sniper_scan_db',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_id', models.TextField(blank=True, null=True)),
                ('project_id', models.TextField(blank=True, null=True)),
                ('ip_address', models.TextField(blank=True, null=True)),
                ('total_dirs', models.IntegerField(default=0)),
                ('username', models.CharField(max_length=256, null=True)),
                ('date_time', models.TextField(blank=True, null=True)),
            ],
        ),
    ]