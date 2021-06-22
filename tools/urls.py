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
from tools import views

app_name = 'tools'

urlpatterns = [
    url(r'^add_group_save',
        views.add_group_save,
        name='add_group_save'),
    url(r'^add_group',
        views.add_group,
        name='add_group'),
    url(r'^add_audit_save',
        views.add_audit_save,
        name='add_audit_save'),
    url(r'^add_audit',
        views.add_audit,
        name='add_audit'),
    url(r'^audit_scripts',
        views.audit_scripts,
        name='audit_scripts'),
    url(r'^sniper_result1',
        views.sniper_result1,
        name='sniper_result1'),
    url(r'^sniper_result2',
        views.sniper_result2,
        name='sniper_result2'),
    url(r'^sniper_log',
        views.sniper_log,
        name='sniper_log'),
    url(r'^sniper_scan_del',
        views.sniper_scan_del,
        name='sniper_scan_del'),
    url(r'^sniper_vuln_del',
        views.sniper_vuln_del,
        name='sniper_vuln_del'),
    url(r'^sniper_delete',
        views.sniper_delete,
        name='sniper_delete'),
    url(r'^sniper_list',
        views.sniper_list,
        name='sniper_list'),
    url(r'^sniper_summary',
        views.sniper_summary,
        name='sniper_summary'),
    url(r'^sniper_launch',
        views.sniper_launch,
        name='sniper_launch'),
    url(r'^sniper_edit',
        views.sniper_edit,
        name='sniper_edit'),
    url(r'^sniper_add',
        views.sniper_add,
        name='sniper_add'),
    url(r'^sslscan/$',
        views.sslscan,
        name='sslscan'),
    url(r'^sslscan_result/$',
        views.sslscan_result,
        name='sslscan_result'),
    url(r'^sslcan_del/$',
        views.sslcan_del,
        name='sslcan_del'),
    url(r'^openvas',
        views.openvas,
        name='openvas'),
    url(r'^openvas_summary',
        views.openvas_summary,
        name='openvas_summary'),
    url(r'^dirsearch_scan',
        views.dirsearch_scan,
        name='dirsearch_scan'),
    url(r'^dirsearch_summary',
        views.dirsearch_summary,
        name='dirsearch_summary'),
    url(r'^dirsearch_del',
        views.dirsearch_del,
        name='dirsearch_del'),
    url(r'^dirsearch_list',
        views.dirsearch_list,
        name='dirsearch_list'),
    url(r'^dirsearch_delete',
        views.dirsearch_delete,
        name='dirsearch_delete'),
    url(r'^nikto/$',
        views.nikto,
        name='nikto'),
    url(r'^nikto_result/$',
        views.nikto_result,
        name='nikto_result'),
    url(r'^nikto_scan_del/$',
        views.nikto_scan_del,
        name='nikto_scan_del'),

    url(r'^nikto_result_vul/$',
        views.nikto_result_vul,
        name='nikto_result_vul'),
    url(r'^nikto_vuln_del/$',
        views.nikto_vuln_del,
        name='nikto_vuln_del'),

    # nmap requests
    url(r'^nmap_scan/$',
        views.nmap_scan,
        name='nmap_scan'),
    url(r'^nmap/$',
        views.nmap,
        name='nmap'),
    url(r'^nmap_result/$',
        views.nmap_result,
        name='nmap_result'),
    url(r'^nmap_scan_del/$',
        views.nmap_scan_del,
        name='nmap_scan_del'),
    url(r'^nmap_vuln_del/$',
        views.nmap_vuln_del,
        name='nmap_vuln_del'),
    #Nmap_Vulners
    url(r'^nmap_vulners_scan/$',
        views.nmap_vulners_scan,
        name='nmap_scan'),
    url(r'^nmap_vulners/$',
        views.nmap_vulners,
        name='nmap_vulners'),
    url(r'^nmap_vulners_port_list/$',
        views.nmap_vulners_port,
        name='nmap_vulners_port'),
]
