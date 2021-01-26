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
from webscanners.zapscanner import views

app_name = 'zapscanner'

urlpatterns = [

    url(r'^zap_scan/',
        views.zap_scan,
        name='zap_scan'),

    url(r'^zap_scan_list/',
        views.zap_scan_list,
        name='zap_scan_list'),

    url(r'^zap_list_vuln/',
        views.zap_list_vuln,
        name='zap_list_vuln'),

    url(r'^zap_vuln_details/',
        views.zap_vuln_details,
        name='zap_vuln_details'),

    url(r'^zap_settings/',
        views.zap_settings,
        name='zap_settings'),

    url(r'^zap_setting_update/',
        views.zap_setting_update,
        name='zap_setting_update'),

    url(r'^del_zap_scan',
        views.del_zap_scan,
        name='del_zap_scan'),

    url(r'^del_zap_vuln',
        views.del_zap_vuln,
        name='del_zap_vuln'),

    url(r'^zap_vuln_check',
        views.zap_vuln_check,
        name='zap_vuln_check'),

    url(r'^sel_login',
        views.sel_login,
        name='sel_login'),

    url(r'save_cookie',
        views.save_cookie,
        name='save_cookie'),

    url(r'exclude_url',
        views.exclude_url,
        name='exclude_url'),

    url(r'^zap_scan_pdf_gen',
        views.zap_scan_pdf_gen,
        name='zap_scan_pdf_gen'),

    url(r'^zap_rescan',
        views.zap_rescan,
        name='zap_rescan'),

    url(r'^cookies_list',
        views.cookies_list,
        name='cookies_list'),

    url(r'^cookies_del',
        views.del_cookies,
        name='cookies_del'),

    url(r'^excluded_url_list',
        views.exluded_url_list,
        name='excluded_url_list'),

    # url(r'^zap_scan_task_launch',
    #     views.zap_scan_task_launch,
    #     name='zap_scan_task_launch'),

    # url(r'^zap_scan_schedule',
    #     views.zap_scan_schedule,
    #     name='zap_scan_schedule'),
    #
    # url(r'^del_zap_scan_schedule',
    #     views.del_zap_scan_schedule,
    #     name='del_zap_scan_schedule'),

    url(r'^export',
        views.export,
        name='export'),

]