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
from projects import views

app_name = 'projects'

urlpatterns = [
    url(r'^create/$',
        views.create,
        name='create'),
    url(r'^create_form/$',
        views.create_form,
        name='create_form'),
    url(r'^create_client/$',
        views.create_client,
        name='create_client'),
    url(r'^create_client_form/$',
        views.create_client_form,
        name='create_client_form'),
    url(r'^edit_client_form/$',
        views.edit_client_form,
        name='edit_client_form'),
    url(r'^edit_project_form/$',
        views.edit_project_form,
        name='edit_project_form'),
    url(r'^$',
        views.projects,
        name='projects'),
    url(r'^list_projects$',
        views.list_projects,
        name='list_projects'),
    url(r'^clients$',
        views.clients,
        name='clients'),
]
