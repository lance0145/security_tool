# Generated by Django 3.0.7 on 2021-03-09 06:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tools', '0007_auto_20210307_2234'),
    ]

    operations = [
        migrations.CreateModel(
            name='openvas_scan_db',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_id', models.TextField(blank=True)),
                ('rescan_id', models.TextField(blank=True, null=True)),
                ('scan_ip', models.TextField(blank=True)),
                ('target_id', models.TextField(blank=True)),
                ('scan_status', models.TextField(blank=True)),
                ('total_vul', models.IntegerField(blank=True, null=True)),
                ('high_vul', models.IntegerField(blank=True, null=True)),
                ('medium_vul', models.IntegerField(blank=True, null=True)),
                ('low_vul', models.IntegerField(blank=True, null=True)),
                ('log_total', models.IntegerField(blank=True, null=True)),
                ('project_id', models.TextField(blank=True)),
                ('date_time', models.DateTimeField(null=True)),
                ('total_dup', models.IntegerField(blank=True, null=True)),
                ('username', models.CharField(max_length=256, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='ov_scan_result_db',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_id', models.TextField(blank=True)),
                ('rescan_id', models.TextField(blank=True, null=True)),
                ('project_id', models.UUIDField(null=True)),
                ('vul_id', models.TextField(blank=True)),
                ('name', models.TextField(blank=True)),
                ('owner', models.TextField(blank=True)),
                ('comment', models.TextField(blank=True)),
                ('creation_time', models.TextField(blank=True)),
                ('modification_time', models.TextField(blank=True)),
                ('user_tags', models.TextField(blank=True)),
                ('host', models.TextField(blank=True)),
                ('port', models.TextField(blank=True)),
                ('nvt', models.TextField(blank=True)),
                ('scan_nvt_version', models.TextField(blank=True)),
                ('threat', models.TextField(blank=True)),
                ('severity', models.TextField(blank=True)),
                ('qod', models.TextField(blank=True)),
                ('description', models.TextField(blank=True)),
                ('term', models.TextField(blank=True)),
                ('keywords', models.TextField(blank=True)),
                ('field', models.TextField(blank=True)),
                ('filtered', models.TextField(blank=True)),
                ('page', models.TextField(blank=True)),
                ('vuln_color', models.TextField(blank=True)),
                ('family', models.TextField(blank=True)),
                ('cvss_base', models.TextField(blank=True)),
                ('cve', models.TextField(blank=True)),
                ('bid', models.TextField(blank=True)),
                ('xref', models.TextField(blank=True)),
                ('tags', models.TextField(blank=True)),
                ('banner', models.TextField(blank=True)),
                ('date_time', models.DateTimeField(null=True)),
                ('false_positive', models.TextField(blank=True, null=True)),
                ('jira_ticket', models.TextField(blank=True, null=True)),
                ('vuln_status', models.TextField(blank=True, null=True)),
                ('dup_hash', models.TextField(blank=True, null=True)),
                ('vuln_duplicate', models.TextField(blank=True, null=True)),
                ('false_positive_hash', models.TextField(blank=True, null=True)),
                ('scanner', models.TextField(default='OpenVAS', editable=False)),
                ('username', models.CharField(max_length=256, null=True)),
            ],
        ),
    ]
