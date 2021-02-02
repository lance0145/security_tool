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
from django.shortcuts import render, HttpResponseRedirect
from django.contrib import messages
import uuid
from projects.models import project_db, project_scan_db, client_db
from webscanners.models import zap_scans_db, zap_scan_results_db, \
    burp_scan_db, burp_scan_result_db, \
    arachni_scan_db, arachni_scan_result_db, \
    netsparker_scan_db, netsparker_scan_result_db, \
    webinspect_scan_db, webinspect_scan_result_db, \
    acunetix_scan_db, acunetix_scan_result_db
from staticscanners.models import dependencycheck_scan_db, dependencycheck_scan_results_db, \
    findbugs_scan_db, findbugs_scan_results_db, \
    bandit_scan_db, bandit_scan_results_db, clair_scan_db, clair_scan_results_db, \
    trivy_scan_db, trivy_scan_results_db, npmaudit_scan_db, npmaudit_scan_results_db, nodejsscan_scan_results_db, \
    nodejsscan_scan_db, tfsec_scan_results_db, tfsec_scan_db, checkmarx_scan_results_db, checkmarx_scan_db, \
    whitesource_scan_db, whitesource_scan_results_db, gitlabsca_scan_results_db, gitlabsast_scan_results_db, \
    gitlabsca_scan_db, gitlabsast_scan_db, semgrepscan_scan_results_db, semgrepscan_scan_db, \
    gitlabcontainerscan_scan_results_db, gitlabcontainerscan_scan_db
from compliance.models import inspec_scan_results_db, inspec_scan_db, dockle_scan_db, dockle_scan_results_db
from networkscanners.models import openvas_scan_db, ov_scan_result_db, nessus_scan_db, nessus_targets_db, nessus_scan_results_db
import datetime
from manual_scan.models import manual_scan_results_db, manual_scans_db
from projects.models import month_db
from itertools import chain
from django.urls import reverse
from dashboard.scans_data import scans_query

project_dat = None


def list_projects(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_projects = project_db.objects.filter(username=username)
    all_clients = client_db.objects.filter(username=username)

    return render(request,
                  'projects.html',
                  {'all_projects': all_projects,
                  'all_clients': all_clients}
                  )

def create_form(request):
    username = request.user.username
    all_clients = client_db.objects.filter(username=username)

    return render(request, 'project_create.html', {'all_clients': all_clients})

def create_client_form(request):
    return render(request, 'create_client.html')

def edit_client_form(request):
    return render(request, 'edit_client.html')

def edit_project_form(request):
    return render(request, 'edit_project.html')

def create_client(request):
    client_id = request.POST.get('client_id', )

    if request.method == 'POST' and client_id:
        client_name = request.POST.get("client_name", )
        client_address = request.POST.get("client_address", )
        client_phone = request.POST.get("client_phone", )
        client_email = request.POST.get("client_email", )
        client_website = request.POST.get("client_website", )
        client_ip = request.POST.get("client_ip", )
        client_note = request.POST.get("client_note", )

        client_db.objects.filter(client_id=client_id
        ).update(
            client_name=client_name,
            client_address=client_address,
            client_phone=client_phone,
            client_email=client_email,
            client_website=client_website,
            client_ip=client_ip,
            client_note=client_note,
        )
        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    if request.method == 'POST':
        username = request.user.username
        client_id = uuid.uuid4()
        client_name = request.POST.get("client_name", )
        client_address = request.POST.get("client_address", )
        client_phone = request.POST.get("client_phone", )
        client_email = request.POST.get("client_email", )
        client_website = request.POST.get("client_website", )
        client_ip = request.POST.get("client_ip", )
        client_note = request.POST.get("client_note", )

        save_client = client_db(username=username,
                                  client_id=client_id,
                                  client_name=client_name,
                                  client_address=client_address,
                                  client_phone=client_phone,
                                  client_email=client_email,
                                  client_website=client_website,
                                  client_ip=client_ip,
                                  client_note=client_note,
                                  )
        save_client.save()

        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    return render(request, 'dashboard/project.html')

def create(request):
    project_id = request.POST.get('proj_id', )

    if request.method == 'POST' and project_id:
        project_name = request.POST.get("project_name")
        project_date = request.POST.get("project_start")
        project_end = request.POST.get("project_end")
        project_owner = request.POST.get("project_owner")
        project_disc = request.POST.get("project_disc")

        project_db.objects.filter(project_id=project_id
        ).update(
            project_name=project_name,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc
        )
        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    if request.method == 'POST':
        username = request.user.username
        project_id = uuid.uuid4()
        project_name = request.POST.get("projectname", )
        project_date = request.POST.get("projectstart", )
        project_end = request.POST.get("projectend", )
        project_owner = request.POST.get("projectowner", )
        project_disc = request.POST.get("project_disc", )
        date_time = datetime.datetime.now()
        client = request.POST.get("client", )
        project_note = request.POST.get("project_note", )

        save_project = project_db(username=username,
                                  project_name=project_name,
                                  project_id=project_id,
                                  project_start=project_date,
                                  project_end=project_end,
                                  project_owner=project_owner,
                                  project_disc=project_disc,
                                  client=client,
                                  project_note=project_note,
                                  date_time=date_time,
                                  total_vuln=0,
                                  total_high=0,
                                  total_medium=0,
                                  total_low=0,
                                  total_open=0,
                                  total_false=0,
                                  total_close=0,
                                  total_net=0,
                                  total_web=0,
                                  total_static=0,
                                  high_net=0,
                                  high_web=0,
                                  high_static=0,
                                  medium_net=0,
                                  medium_web=0,
                                  medium_static=0,
                                  low_net=0,
                                  low_web=0,
                                  low_static=0)
        save_project.save()

        # messages.success(request, "Project Created")
        all_month_data_display = month_db.objects.filter(username=username)

        if len(all_month_data_display) == 0:
            save_months_data = month_db(username=username,
                                        project_id=project_id,
                                        month=datetime.datetime.now().month,
                                        high=0,
                                        medium=0,
                                        low=0
                                        )
            save_months_data.save()

        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    return render(request, 'dashboard/project.html')

def projects(request):

    client_id = request.GET["client_id"]

    if request.method == 'GET' and client_id:

        edit_client = client_db.objects.filter(client_id=client_id)
        print("************************************************************************************************************")
        print(edit_client[0].client_note)
        return render(request,
                  'edit_client.html',
                  {'edit_client': edit_client[0]}
                  )

    if request.method == 'POST':
        
        client_id = request.POST.get("client_id", )
        client_proj = client_db.objects.filter(client_id=client_id)
        client_proj.delete()

        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    project_id = request.GET["proj_id"]
    
    if request.method == 'GET' and project_id:

        edit_proj = project_db.objects.filter(project_id=project_id)
        return render(request,
                  'edit_project.html',
                  {'edit_proj': edit_proj[0]}
                  )

    if request.method == 'POST':

        project_id = request.POST.get("proj_id", )
        del_proj = project_db.objects.filter(project_id=project_id)
        del_proj.delete()

        burp = burp_scan_db.objects.filter(project_id=project_id)
        burp.delete()
        burp_result_data = burp_scan_result_db.objects.filter(project_id=project_id)
        burp_result_data.delete()

        zap = zap_scans_db.objects.filter(project_id=project_id)
        zap.delete()
        zap_result = zap_scan_results_db.objects.filter(project_id=project_id)
        zap_result.delete()

        arachni = arachni_scan_db.objects.filter(project_id=project_id)
        arachni.delete()
        arachni_result = arachni_scan_result_db.objects.filter(project_id=project_id)
        arachni_result.delete()

        webinspect = webinspect_scan_db.objects.filter(project_id=project_id)
        webinspect.delete()
        webinspect_result = webinspect_scan_result_db.objects.filter(project_id=project_id)
        webinspect_result.delete()

        netsparker = netsparker_scan_db.objects.filter(project_id=project_id)
        netsparker.delete()
        netsparker_result = netsparker_scan_result_db.objects.filter(project_id=project_id)
        netsparker_result.delete()

        acunetix = acunetix_scan_db.objects.filter(project_id=project_id)
        acunetix.delete()
        acunetix_result = acunetix_scan_result_db.objects.filter(project_id=project_id)
        acunetix_result.delete()

        dependency_check = dependencycheck_scan_db.objects.filter(project_id=project_id)
        dependency_check.delete()
        dependency_check_result = dependencycheck_scan_results_db.objects.filter(project_id=project_id)
        dependency_check_result.delete()

        findbugs = findbugs_scan_db.objects.filter(project_id=project_id)
        findbugs.delete()
        findbugs_result = findbugs_scan_results_db.objects.filter(project_id=project_id)
        findbugs_result.delete()

        bandit = bandit_scan_db.objects.filter(project_id=project_id)
        bandit.delete()
        bandit_result = bandit_scan_results_db.objects.filter(project_id=project_id)
        bandit_result.delete()

        clair = clair_scan_db.objects.filter(project_id=project_id)
        clair.delete()
        clair_result = clair_scan_results_db.objects.filter(project_id=project_id)
        clair_result.delete()

        trivy = trivy_scan_db.objects.filter(project_id=project_id)
        trivy.delete()
        trivy_result = trivy_scan_results_db.objects.filter(project_id=project_id)
        trivy_result.delete()

        npmaudit = npmaudit_scan_db.objects.filter(project_id=project_id)
        npmaudit.delete()
        npmaudit_result = npmaudit_scan_results_db.objects.filter(project_id=project_id)
        npmaudit_result.delete()

        nodejsscan = nodejsscan_scan_db.objects.filter(project_id=project_id)
        nodejsscan.delete()
        nodejsscan_result = nodejsscan_scan_results_db.objects.filter(project_id=project_id)
        nodejsscan_result.delete()

        tfsec = tfsec_scan_db.objects.filter(project_id=project_id)
        tfsec.delete()
        tfsec_result = tfsec_scan_results_db.objects.filter(project_id=project_id)
        tfsec_result.delete()

        whitesource = whitesource_scan_db.objects.filter(project_id=project_id)
        whitesource.delete()
        whitesource_result = whitesource_scan_results_db.objects.filter(project_id=project_id)
        whitesource_result.delete()

        gitlabsca = gitlabsca_scan_db.objects.filter(project_id=project_id)
        gitlabsca.delete()
        gitlabsca_result = gitlabsca_scan_results_db.objects.filter(project_id=project_id)
        gitlabsca_result.delete()

        gitlabsast = gitlabsast_scan_db.objects.filter(project_id=project_id)
        gitlabsast.delete()
        gitlabsast_result = gitlabsast_scan_results_db.objects.filter(project_id=project_id)
        gitlabsast_result.delete()

        gitlabcontainerscan = gitlabcontainerscan_scan_db.objects.filter(project_id=project_id)
        gitlabcontainerscan.delete()
        gitlabcontainerscan_result = gitlabcontainerscan_scan_results_db.objects.filter(project_id=project_id)
        gitlabcontainerscan_result.delete()

        checkmarx = checkmarx_scan_db.objects.filter(project_id=project_id)
        checkmarx.delete()
        checkmarx_result = checkmarx_scan_results_db.objects.filter(project_id=project_id)
        checkmarx_result.delete()

        semgrepscan = semgrepscan_scan_db.objects.filter(project_id=project_id)
        semgrepscan.delete()
        semgrepscan_result = semgrepscan_scan_results_db.objects.filter(project_id=project_id)
        semgrepscan_result.delete()

        inspec = inspec_scan_db.objects.filter(project_id=project_id)
        inspec.delete()
        inspec_result = inspec_scan_results_db.objects.filter(project_id=project_id)
        inspec_result.delete()

        dockle = dockle_scan_db.objects.filter(project_id=project_id)
        dockle.delete()
        dockle_result = dockle_scan_results_db.objects.filter(project_id=project_id)
        dockle_result.delete()

        openvas = openvas_scan_db.objects.filter(project_id=project_id)
        openvas.delete()
        openvas_result = ov_scan_result_db.objects.filter(project_id=project_id)
        openvas_result.delete()

        nessus = nessus_scan_db.objects.filter(project_id=project_id)
        nessus.delete()

        nessus_result = nessus_targets_db.objects.filter(project_id=project_id)
        nessus_result.delete()

        nessus_scan_results = nessus_scan_results_db.objects.filter(project_id=project_id)
        nessus_scan_results.delete()

        pentest = manual_scan_results_db.objects.filter(project_id=project_id)
        pentest.delete()

        pentest_dat = manual_scans_db.objects.filter(project_id=project_id)
        pentest_dat.delete()

        month_db_del = month_db.objects.filter(project_id=project_id)
        month_db_del.delete()

        # messages.success(request, "Deleted Project")

        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    return render(request, 'dashboard/project.html', {'all_projects': all_projects})


def project_edit(request):
    """

    :param request:
    :return:
    """
    global project_dat
    if request.method == 'GET':
        project_id = request.GET['project_id']
        username = request.user.username
        project_dat = project_db.objects.filter(project_id=project_id, username=username)

    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        project_name = request.POST.get("projectname")
        project_date = request.POST.get("projectstart")
        project_end = request.POST.get("projectend")
        project_owner = request.POST.get("projectowner")
        project_disc = request.POST.get("project_disc")

        project_db.objects.filter(
            project_id=project_id
        ).update(
            project_name=project_name,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc
        )
        return HttpResponseRedirect(reverse('projects:projects') + '?proj_id=%s' % project_id)
    return render(request,
                  'edit_project.html',
                #   'project_edit.html',
                  {'project_dat': project_dat}
                  )
