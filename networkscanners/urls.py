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

from django.conf.urls import url
from networkscanners import views

app_name = 'networkscanners'

urlpatterns = [
    url(r'^sniper',
        views.sniper,
        name='sniper'),
    url(r'^$',
        views.index,
        name='index'),
    url(r'^vul_details/',
        views.scan_vul_details,
        name='vul_details'),
    url(r'^launch_scan',
        views.launch_scan,
        name='launch_scan'),
    url(r'^scan_del',
        views.scan_del,
        name='scan_del'),
    url(r'^ip_scan',
        views.ip_scan,
        name='ip_scan'),
    url(r'^open_vas',
        views.open_vas,
        name='open_vas'),
    url(r'^nikto',
        views.nikto,
        name='nikto'),
    url(r'^dirsearch',
        views.dirsearch,
        name='dirsearch'),
    url(r'^nv_setting',
        views.nv_setting,
        name='nv_setting'),
    url(r'^nv_details',
        views.nv_details,
        name='nv_details'),
    url(r'^openvas_setting',
        views.openvas_setting,
        name='openvas_setting'),
    url(r'^server_setting',
        views.server_setting,
        name='server_setting'),
    url(r'^openvas_details',
        views.openvas_details,
        name='openvas_details'),
    url(r'^del_vuln',
        views.del_vuln,
        name='del_vuln'),
    url(r'^vuln_check',
        views.vuln_check,
        name='vuln_check'),
    url(r'^OpenVAS_xml_upload',
        views.OpenVAS_xml_upload,
        name='OpenVAS_xml_upload'),
    url(r'^net_scan_schedule',
        views.net_scan_schedule,
        name='net_scan_schedule'),
    url(r'^del_net_scan_schedule',
        views.del_net_scan_schedule,
        name='del_net_scan_schedule'),
    url(r'^check_vul_exist',
        views.check_vul_exist,
        name='check_vul_exist'),
]
