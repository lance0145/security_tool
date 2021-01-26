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
from dashboard import views
from webscanners import web_views

app_name = 'dashboard'

urlpatterns = [

    url(r'^login/$',
        web_views.login,
        name='login'),
    url(r'^auth/$',
        web_views.auth_view,
        name='auth'),
    url(r'^logout/$',
        web_views.logout,
        name='logout'),
    url(r'^loggedin/$',
        web_views.loggedin,
        name='loggedin'),
    url(r'^signup/$',
        web_views.signup,
        name='signup'),

    url(r'^$',
        views.dashboard,
        name='dashboard'),
    url(r'^dashboard/$',
        views.dashboard,
        name='dashboard'),
    url(r'^project_dashboard/$',
        views.project_dashboard,
        name='project_dashboard'),
    url(r'^proj_data/$',
        views.proj_data,
        name='proj_data'),
    url(r'^all_high_vuln/$',
        views.all_high_vuln,
        name='all_high_vuln'),
    url(r'^export/$',
        views.export,
        name='export')


]
