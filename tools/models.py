# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

from __future__ import unicode_literals

from django.db import models


# SSLScan Model.
class sslscan_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    sslscan_output = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)


# Nikto Models
class nikto_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    nikto_scan_output = models.TextField(blank=True, null=True)
    date_time = models.TextField(null=True, blank=True)
    username = models.CharField(max_length=256, null=True)


class nikto_vuln_db(models.Model):
    vuln_id = models.UUIDField(blank=True, null=True)
    scan_id = models.UUIDField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    discription = models.TextField(blank=True, null=True)
    targetip = models.TextField(blank=True, null=True)
    hostname = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    uri = models.TextField(blank=True, null=True)
    httpmethod = models.TextField(blank=True, null=True)
    testlinks = models.TextField(blank=True, null=True)
    osvdb = models.TextField(blank=True, null=True)
    false_positive = models.TextField(null=True, blank=True)
    jira_ticket = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    date_time = models.TextField(null=True, blank=True)
    username = models.CharField(max_length=256, null=True)



# Nmap tool models
class nmap_scan_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_ip = models.TextField(blank=True, null=True)
    total_ports = models.TextField(blank=True, null=True)
    total_open_ports = models.TextField(blank=True, null=True)
    total_close_ports = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)
    date_time = models.TextField(null=True, blank=True)


class nmap_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    state = models.TextField(blank=True, null=True)
    reason = models.TextField(blank=True, null=True)
    reason_ttl = models.TextField(blank=True, null=True)
    version = models.TextField(blank=True, null=True)
    extrainfo = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    conf = models.TextField(blank=True, null=True)
    method = models.TextField(blank=True, null=True)
    type_p = models.TextField(blank=True, null=True)
    osfamily = models.TextField(blank=True, null=True)
    vendor = models.TextField(blank=True, null=True)
    osgen = models.TextField(blank=True, null=True)
    accuracy = models.TextField(blank=True, null=True)
    cpe = models.TextField(blank=True, null=True)
    used_state = models.TextField(blank=True, null=True)
    used_portid = models.TextField(blank=True, null=True)
    used_proto = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)
    date_time = models.TextField(null=True, blank=True)

# NOTE[gmedian]: just base on the previous existing table in order not to make anything non-working
class nmap_vulners_port_result_db(nmap_result_db):
    vulners_extrainfo = models.TextField(blank=True, null=True)

# dirsearch tool models
class dirsearch_scan_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    total_dirs = models.IntegerField(default=0)
    username = models.CharField(max_length=256, null=True)
    date_time = models.TextField(null=True, blank=True)

class dirsearch_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    date_time = models.TextField(null=True, blank=True)
    url = models.TextField(null=True, blank=True)
    ip_address = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    size = models.TextField(blank=True, null=True)
    redirection = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)

class openvas_result_db(models.Model):
    scan_id = models.TextField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    project_id = models.UUIDField(null=True)
    vul_id = models.TextField(blank=True)
    name = models.TextField(blank=True)
    owner = models.TextField(blank=True)
    comment = models.TextField(blank=True)
    creation_time = models.TextField(blank=True)
    modification_time = models.TextField(blank=True)
    user_tags = models.TextField(blank=True)
    host = models.TextField(blank=True)
    port = models.TextField(blank=True)
    nvt = models.TextField(blank=True)
    scan_nvt_version = models.TextField(blank=True)
    threat = models.TextField(blank=True)
    severity = models.TextField(blank=True)
    qod = models.TextField(blank=True)
    description = models.TextField(blank=True)
    term = models.TextField(blank=True)
    keywords = models.TextField(blank=True)
    field = models.TextField(blank=True)
    filtered = models.TextField(blank=True)
    page = models.TextField(blank=True)
    vuln_color = models.TextField(blank=True)
    family = models.TextField(blank=True)
    cvss_base = models.TextField(blank=True)
    cve = models.TextField(blank=True)
    bid = models.TextField(blank=True)
    xref = models.TextField(blank=True)
    tags = models.TextField(blank=True)
    banner = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    false_positive = models.TextField(null=True, blank=True)
    jira_ticket = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    scanner = models.TextField( default='OpenVAS', editable=False)
    username = models.CharField(max_length=256, null=True)
    ip_address = models.TextField(blank=True, null=True)

class openvas_scan_db(models.Model):
    scan_id = models.TextField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_ip = models.TextField(blank=True)
    target_id = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    log_total = models.IntegerField(blank=True, null=True)
    project_id = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    total_dup = models.IntegerField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)
    ip_address = models.TextField(blank=True, null=True)

# Sniper tool models
class sniper_config_db(models.Model):
    config_id = models.TextField(blank=True, null=True)
    config_name = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    script = models.TextField(blank=True, null=True)
    option1 = models.TextField(blank=True, null=True)
    option2 = models.TextField(blank=True, null=True)
    log1 = models.TextField(blank=True, null=True)
    log2 = models.TextField(blank=True, null=True)
    result1 = models.TextField(blank=True, null=True)
    result2 = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)
    date_time = models.TextField(null=True, blank=True)
    project_id = models.TextField(blank=True, null=True)

class sniper_scan_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    total_sniper = models.IntegerField(default=0)
    username = models.CharField(max_length=256, null=True)
    date_time = models.TextField(null=True, blank=True)
    config_id = models.TextField(blank=True, null=True)
    config_name = models.TextField(blank=True, null=True)

class sniper_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    vuln_id = models.TextField(blank=True, null=True)
    config_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    date_time = models.TextField(null=True, blank=True)
    ip_address = models.TextField(blank=True, null=True)
    output = models.TextField(blank=True, null=True)
    result = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)