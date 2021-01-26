# -*- coding: utf-8 -*-
# Copyright (C) 20210125 Allan Abendanio
#
# Email:   lance0145@gmail.com
#
# This file is part of Afovos Project.

from __future__ import unicode_literals

from django.db import models
from django.db.models import Func, F, Sum


class project_db(models.Model):
    project_id = models.TextField(blank=True)
    project_name = models.TextField(blank=True)
    project_start = models.TextField(blank=True)
    project_end = models.TextField(blank=True)
    project_owner = models.TextField(blank=True)
    project_disc = models.TextField(blank=True)
    project_status = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    total_vuln = models.IntegerField(blank=True, null=True)
    total_high = models.IntegerField(blank=True, null=True)
    total_medium = models.IntegerField(blank=True, null=True)
    total_low = models.IntegerField(blank=True, null=True)
    total_open = models.IntegerField(blank=True, null=True)
    total_false = models.IntegerField(blank=True, null=True)
    total_close = models.IntegerField(blank=True, null=True)
    total_net = models.IntegerField(blank=True, null=True)
    total_web = models.IntegerField(blank=True, null=True)
    total_static = models.IntegerField(blank=True, null=True)
    high_net = models.IntegerField(blank=True, null=True)
    high_web = models.IntegerField(blank=True, null=True)
    high_static = models.IntegerField(blank=True, null=True)
    medium_net = models.IntegerField(blank=True, null=True)
    medium_web = models.IntegerField(blank=True, null=True)
    medium_static = models.IntegerField(blank=True, null=True)
    low_net = models.IntegerField(blank=True, null=True)
    low_web = models.IntegerField(blank=True, null=True)
    low_static = models.IntegerField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)


class project_scan_db(models.Model):
    project_url = models.TextField(blank=True) #this is scan url
    project_ip = models.TextField(blank=True)
    scan_type = models.TextField(blank=True)
    project_id = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)


class Month(Func):
    function = 'EXTRACT'
    template = '%(function)s(MONTH from %(expressions)s)'
    output_field = models.IntegerField()

class MonthSqlite(Func):
    function = 'STRFTIME'
    template = '%(function)s("%%m", %(expressions)s)'
    output_field = models.CharField()

class month_db(models.Model):
    month = models.TextField(blank=True, null=True)
    high = models.IntegerField(blank=True, default=0)
    medium = models.IntegerField(blank=True, default=0)
    low = models.IntegerField(blank=True, default=0)
    project_id = models.TextField(blank=True, default=0)
    username = models.CharField(max_length=256, null=True)

class client_db(models.Model):
    name = models.TextField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    phone = models.TextField(blank=True, null=True)
    email = models.TextField(blank=True, null=True)
    website = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    url = models.TextField(blank=True, null=True)

class note_db(models.Model):
    name = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    date = models.DateTimeField(null=True)

