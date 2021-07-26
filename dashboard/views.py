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


""" Author: Anand Tiwari """

from __future__ import unicode_literals

from django.db.models import Sum
from webscanners.models import zap_scans_db, \
    burp_scan_db, \
    arachni_scan_db, \
    netsparker_scan_db, \
    webinspect_scan_db, \
    zap_scan_results_db, \
    burp_scan_result_db, \
    arachni_scan_result_db, \
    netsparker_scan_result_db, \
    webinspect_scan_result_db, \
    acunetix_scan_db, acunetix_scan_result_db
from manual_scan.models import manual_scans_db, manual_scan_results_db

from staticscanners.models import dependencycheck_scan_db, \
    bandit_scan_db, bandit_scan_results_db, \
    findbugs_scan_db, \
    dependencycheck_scan_results_db, \
    findbugs_scan_results_db, \
    clair_scan_results_db, \
    clair_scan_db, \
    trivy_scan_results_db, \
    trivy_scan_db, \
    npmaudit_scan_db, \
    npmaudit_scan_results_db, \
    nodejsscan_scan_db, \
    nodejsscan_scan_results_db, \
    semgrepscan_scan_db, \
    semgrepscan_scan_results_db, \
    tfsec_scan_db, \
    tfsec_scan_results_db, \
    whitesource_scan_db, \
    whitesource_scan_results_db, \
    checkmarx_scan_db, \
    checkmarx_scan_results_db, \
    gitlabsast_scan_db, \
    gitlabsast_scan_results_db, \
    gitlabsca_scan_db, \
    gitlabsca_scan_results_db, \
    gitlabcontainerscan_scan_db, \
    gitlabcontainerscan_scan_results_db
from networkscanners.models import openvas_scan_db, \
    nessus_scan_db, \
    ov_scan_result_db, \
    nessus_report_db, \
    nessus_scan_results_db
from compliance.models import inspec_scan_db, dockle_scan_db
from projects.models import project_db
from django.shortcuts import render, HttpResponse, HttpResponseRedirect
from itertools import chain
import datetime
from webscanners.resources import AllResource
from notifications.models import Notification
from django.contrib.auth import user_logged_in
from django.contrib.auth.models import User
from django.urls import reverse
from dashboard.scans_data import scans_query
from projects.models import Month, MonthSqlite, client_db, month_db
from tools.models import audit_question_db, audit_db

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """
    current_month = ''
    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    scanners = 'vscanners'
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

    current_year = datetime.datetime.now().year

    for project in all_project:
        proj_id = project.project_id
        all_date_data = (project_db.objects
                         .annotate(month=Month('date_time'))
                         .values('month').annotate(total_high=Sum('total_high')).annotate(total_medium=Sum('total_medium')).annotate(total_low=Sum('total_low')).order_by("month")
                         )

        try:
            # critical = all_date_data.first()['total_crit']
            critical = None
            high = all_date_data.first()['total_high']
            medium = all_date_data.first()['total_medium']
            low = all_date_data.first()['total_low']
            info = None
            # info = all_date_data.first()['total_info']
        except:
            all_date_data = (project_db.objects
                             .annotate(month=MonthSqlite('date_time'))
                             .values('month').annotate(total_high=Sum('total_high')).annotate(
                total_medium=Sum('total_medium')).annotate(total_low=Sum('total_low')).order_by("month")
                             )
            # critical = all_date_data.first()['total_crit']
            critical = None
            high = all_date_data.first()['total_high']
            medium = all_date_data.first()['total_medium']
            low = all_date_data.first()['total_low']
            # info = all_date_data.first()['total_info']
            info = None

        all_month_data_display = month_db.objects.filter(username=username)

        if len(all_month_data_display) == 0:
            add_data = month_db(username=username, project_id=proj_id, month=current_month, critical=critical, high=high, medium=medium,
                                low=low, info=info)
            add_data.save()

        for data in all_month_data_display:
            current_month = datetime.datetime.now().month
            if int(current_month) == 1:
                month_db.objects.filter(username=username, project_id=proj_id, month='2').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='3').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='4').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='5').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='6').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='7').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='8').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='9').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='10').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='11').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='12').delete()

            match_data = month_db.objects.filter(username=username, project_id=proj_id, month=current_month)
            if len(match_data) == 0:
                # add_data = month_db(username=username, project_id=proj_id, month=current_month, critical=critical, high=high, medium=medium, low=low, info=info)
                add_data = month_db(username=username, project_id=proj_id, month=current_month, high=high, medium=medium, low=low)
                add_data.save()

            elif int(data.month) == int(current_month):
                month_db.objects.filter(username=username, project_id=proj_id, month=current_month).update(high=high,
                                                                                                           medium=medium,
                                                                                                           low=low)

        total_vuln = scans_query.all_vuln(username=username, project_id=proj_id, query='total')
        total_crit = scans_query.all_vuln(username=username, project_id=proj_id, query='critical')
        total_high = scans_query.all_vuln(username=username, project_id=proj_id, query='high')
        total_medium = scans_query.all_vuln(username=username, project_id=proj_id, query='medium')
        total_low = scans_query.all_vuln(username=username, project_id=proj_id, query='minimal')
        total_info = scans_query.all_vuln(username=username, project_id=proj_id, query='very minimal')

        total_open = scans_query.all_vuln_count_data(username, proj_id, query='Open')
        total_close = scans_query.all_vuln_count_data(username, proj_id, query='Closed')
        total_false = scans_query.all_vuln_count_data(username, proj_id, query='false')

        total_net = scans_query.all_net(username, proj_id, query='total')
        total_web = scans_query.all_web(username, proj_id, query='total')
        total_static = scans_query.all_static(username, proj_id, query='total')

        high_net = scans_query.all_net(username, proj_id, query='high')
        high_web = scans_query.all_web(username, proj_id, query='high')
        high_static = scans_query.all_static(username, proj_id, query='high')

        medium_net = scans_query.all_net(username, proj_id, query='medium')
        medium_web = scans_query.all_web(username, proj_id, query='medium')
        medium_static = scans_query.all_static(username, proj_id, query='medium')

        low_net = scans_query.all_net(username, proj_id, query='minimal')
        low_web = scans_query.all_web(username, proj_id, query='minimal')
        low_static = scans_query.all_static(username, proj_id, query='minimal')

        project_db.objects.filter(username=username,
                                  project_id=proj_id
                                  ).update(total_vuln=total_vuln,
                                           total_open=total_open,
                                           total_close=total_close,
                                           total_false=total_false,
                                           total_net=total_net,
                                           total_web=total_web,
                                           total_static=total_static,
                                           total_high=total_high,
                                           total_medium=total_medium,
                                           total_low=total_low,
                                           high_net=high_net,
                                           high_web=high_web,
                                           high_static=high_static,
                                           medium_net=medium_net,
                                           medium_web=medium_web,
                                           medium_static=medium_static,
                                           low_net=low_net,
                                           low_web=low_web,
                                           low_static=low_static,
                                           )

    user = user_logged_in
    all_notify = Notification.objects.unread()

    all_month_data_display = month_db.objects.filter(username=username).values('month', 'high', 'medium', 'low').distinct()

    all_clients = client_db.objects.filter(username=username)
    all_questions = audit_question_db.objects.all
    all_clients_audits = []
    for client in all_clients:
        all_audits = audit_db.objects.filter(client_id=client.client_id)
        all_clients_audits.append(all_audits)

    return render(request,
                  'dashboard/index.html',
                  {'all_clients': all_clients,
                   'all_clients_audits': all_clients_audits,
                   'all_questions': all_questions,
                   'all_project': all_project,
                   'scanners': scanners,
                   'total_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_vuln')),
                   'open_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_open')),
                   'close_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_close')),
                   'false_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_false')),
                   'net_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_net')),
                   'web_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_web')),
                   'static_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_static')),
                   'high_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_high')),
                   'medium_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_medium')),
                   'low_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_low')),
                   'high_net_count_project': project_db.objects.filter(username=username).aggregate(Sum('high_net')),
                   'high_web_count_project': project_db.objects.filter(username=username).aggregate(Sum('high_web')),
                   'high_static_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('high_static')),
                   'medium_net_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('medium_net')),
                   'medium_web_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('medium_web')),
                   'medium_static_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('medium_static')),
                   'low_net_count_project': project_db.objects.filter(username=username).aggregate(Sum('low_net')),
                   'low_web_count_project': project_db.objects.filter(username=username).aggregate(Sum('low_web')),
                   'low_static_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('low_static')),
                   'all_month_data_display': all_month_data_display,
                   'current_year': current_year,
                   'message': all_notify
                   })


def project_dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """

    scanners = 'vscanners'
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

    all_notify = Notification.objects.unread()

    return render(request,
                  'dashboard/project.html',
                  {'all_project': all_project,
                   'scanners': scanners,
                   'message': all_notify
                   })


def proj_data(request):
    """
    The function pulling all project data from database.
    :param request:
    :return:
    """
    username = request.user.username
    all_project = project_db.objects.filter(username=username)
    if request.GET['project_id']:
        project_id = request.GET['project_id']
    else:
        project_id = ''

    project_dat = project_db.objects.filter(username=username, project_id=project_id)
    burp = burp_scan_db.objects.filter(username=username, project_id=project_id)
    zap = zap_scans_db.objects.filter(username=username, project_id=project_id)
    arachni = arachni_scan_db.objects.filter(username=username, project_id=project_id)
    webinspect = webinspect_scan_db.objects.filter(username=username, project_id=project_id)
    netsparker = netsparker_scan_db.objects.filter(username=username, project_id=project_id)
    acunetix = acunetix_scan_db.objects.filter(username=username, project_id=project_id)

    dependency_check = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id)
    findbugs = findbugs_scan_db.objects.filter(username=username, project_id=project_id)
    clair = clair_scan_db.objects.filter(username=username, project_id=project_id)
    trivy = trivy_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabsast = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabcontainerscan = gitlabcontainerscan_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabsca = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id)
    npmaudit = npmaudit_scan_db.objects.filter(username=username, project_id=project_id)
    nodejsscan = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id)
    semgrepscan = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id)
    tfsec = tfsec_scan_db.objects.filter(username=username, project_id=project_id)
    whitesource = whitesource_scan_db.objects.filter(username=username, project_id=project_id)
    checkmarx = checkmarx_scan_db.objects.filter(username=username, project_id=project_id)
    bandit = bandit_scan_db.objects.filter(username=username, project_id=project_id)

    web_scan_dat = chain(burp, zap, arachni, webinspect, netsparker, acunetix)
    static_scan = chain(dependency_check, findbugs, clair, trivy, gitlabsast, gitlabcontainerscan, gitlabsca, npmaudit,
                        nodejsscan, semgrepscan, tfsec, whitesource, checkmarx, bandit)
    openvas_dat = openvas_scan_db.objects.filter(username=username, project_id=project_id)
    nessus_dat = nessus_scan_db.objects.filter(username=username, project_id=project_id)

    network_dat = chain(openvas_dat, nessus_dat)

    inspec_dat = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    dockle_dat = dockle_scan_db.objects.filter(username=username, project_id=project_id)

    compliance_dat = chain(inspec_dat, dockle_dat)

    all_comp_inspec = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    all_comp_dockle = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = manual_scans_db.objects.filter(username=username, project_id=project_id)

    all_notify = Notification.objects.unread()

    all_high = scans_query.all_vuln(username=username, project_id=project_id, query='high')#, scans_query.all_vuln(username=username, project_id=project_id, query='critical')
    all_medium = scans_query.all_vuln(username=username, project_id=project_id, query='medium')
    all_low = scans_query.all_vuln(username=username, project_id=project_id, query='minimal')#, scans_query.all_vuln(username=username, project_id=project_id, query='very minimal')

    total = all_high, all_medium, all_low

    tota_vuln = sum(total)

    return render(request,
                  'dashboard/project.html',
                  {'project_id': project_id,
                   'tota_vuln': tota_vuln,
                   'all_vuln': scans_query.all_vuln(username=username, project_id=project_id, query='total'),
                   'total_web': scans_query.all_web(username=username, project_id=project_id, query='total'),
                   'total_static': scans_query.all_static(username=username, project_id=project_id, query='total'),
                   'total_network': scans_query.all_net(username=username, project_id=project_id, query='total'),
                   'all_high': all_high,
                   'all_medium': all_medium,
                   'all_low': all_low,
                   'all_web_high': scans_query.all_web(username=username, project_id=project_id, query='high'),
                   'all_web_medium': scans_query.all_web(username=username, project_id=project_id, query='medium'),
                   'all_network_medium': scans_query.all_net(username=username, project_id=project_id, query='medium'),
                   'all_network_high': scans_query.all_net(username=username, project_id=project_id, query='high'),
                   'all_web_low': scans_query.all_web(username=username, project_id=project_id, query='minimal'),
                   'all_network_low': scans_query.all_net(username=username, project_id=project_id, query='minimal'),
                   'all_project': all_project,
                   'project_dat': project_dat,
                   'web_scan_dat': web_scan_dat,
                   'all_static_high': scans_query.all_static(username=username, project_id=project_id, query='high'),
                   'all_static_medium': scans_query.all_static(username=username, project_id=project_id,
                                                               query='medium'),
                   'all_static_low': scans_query.all_static(username=username, project_id=project_id, query='minimal'),
                   'static_scan': static_scan,
                   'zap': zap,
                   'burp': burp,
                   'arachni': arachni,
                   'webinspect': webinspect,
                   'netsparker': netsparker,
                   'acunetix': acunetix,
                   'dependency_check': dependency_check,
                   'findbugs': findbugs,
                   'bandit': bandit,
                   'clair': clair,
                   'trivy': trivy,
                   'gitlabsast': gitlabsast,
                   'gitlabcontainerscan': gitlabcontainerscan,
                   'gitlabsca': gitlabsca,
                   'npmaudit': npmaudit,
                   'nodejsscan': nodejsscan,
                   'semgrepscan': semgrepscan,
                   'tfsec': tfsec,
                   'whitesource': whitesource,
                   'checkmarx': checkmarx,
                   'pentest': pentest,
                   'network_dat': network_dat,
                   'all_zap_scan': int(scans_query.all_zap(username=username, project_id=project_id, query='total')),
                   'all_burp_scan': int(scans_query.all_burp(username=username, project_id=project_id, query='total')),
                   'all_arachni_scan': int(
                       scans_query.all_arachni(username=username, project_id=project_id, query='total')),
                   'all_acunetix_scan': int(
                       scans_query.all_acunetix(username=username, project_id=project_id, query='total')),
                   'all_netsparker_scan': int(
                       scans_query.all_netsparker(username=username, project_id=project_id, query='total')),
                   'all_openvas_scan': int(
                       scans_query.all_openvas(username=username, project_id=project_id, query='total')),
                   'all_nessus_scan': int(
                       scans_query.all_nessus(username=username, project_id=project_id, query='total')),
                   'all_dependency_scan': int(
                       scans_query.all_dependency(username=username, project_id=project_id, query='total')),
                   'all_findbugs_scan': int(
                       scans_query.all_findbugs(username=username, project_id=project_id, query='total')),
                   'all_clair_scan': int(
                       scans_query.all_clair(username=username, project_id=project_id, query='total')),
                   'all_trivy_scan': int(
                       scans_query.all_trivy(username=username, project_id=project_id, query='total')),
                   'all_gitlabsast_scan': int(
                       scans_query.all_gitlabsast(username=username, project_id=project_id, query='total')),
                   'all_gitlabcontainerscan_scan': int(
                       scans_query.all_gitlabcontainerscan(username=username, project_id=project_id, query='total')),
                   'all_gitlabsca_scan': int(
                       scans_query.all_gitlabsca(username=username, project_id=project_id, query='total')),
                   'all_npmaudit_scan': int(
                       scans_query.all_npmaudit(username=username, project_id=project_id, query='total')),
                   'all_nodejsscan_scan': int(
                       scans_query.all_nodejsscan(username=username, project_id=project_id, query='total')),
                   'all_semgrepscan_scan': int(
                       scans_query.all_semgrepscan(username=username, project_id=project_id, query='total')),
                   'all_tfsec_scan': int(
                       scans_query.all_tfsec(username=username, project_id=project_id, query='total')),
                   'all_whitesource_scan': int(
                       scans_query.all_whitesource(username=username, project_id=project_id, query='total')),
                   'all_checkmarx_scan': int(
                       scans_query.all_checkmarx(username=username, project_id=project_id, query='total')),
                   'all_webinspect_scan': int(
                       scans_query.all_webinspect(username=username, project_id=project_id, query='total')),

                   'all_compliance_failed': scans_query.all_compliance(username=username, project_id=project_id,
                                                                       query='failed'),
                   'all_compliance_passed': scans_query.all_compliance(username=username, project_id=project_id,
                                                                       query='passed'),
                   'all_compliance_skipped': scans_query.all_compliance(username=username, project_id=project_id,
                                                                        query='skipped'),
                   'total_compliance': scans_query.all_compliance(username=username, project_id=project_id,
                                                                  query='total'),

                   'openvas_dat': openvas_dat,
                   'nessus_dat': nessus_dat,

                   'all_compliance': all_compliance_seg,

                   'compliance_dat': compliance_dat,
                   'inspec_dat': inspec_dat,
                   'dockle_dat': dockle_dat,

                   'all_zap_high': zap_scans_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_zap_low': zap_scans_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_zap_medium': zap_scans_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_webinspect_high': webinspect_scan_db.objects.filter(username=username,
                                                                            project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_webinspect_low': webinspect_scan_db.objects.filter(username=username,
                                                                           project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_webinspect_medium': webinspect_scan_db.objects.filter(username=username,
                                                                              project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_acunetix_high': acunetix_scan_db.objects.filter(username=username,
                                                                        project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_acunetix_low': acunetix_scan_db.objects.filter(username=username,
                                                                       project_id=project_id).aggregate(Sum('low_vul')),
                   'all_acunetix_medium': acunetix_scan_db.objects.filter(username=username,
                                                                          project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_burp_high': burp_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_burp_low': burp_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_burp_medium': burp_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_arachni_high': arachni_scan_db.objects.filter(username=username,
                                                                      project_id=project_id).aggregate(Sum('high_vul')),
                   'all_arachni_low': arachni_scan_db.objects.filter(username=username,
                                                                     project_id=project_id).aggregate(Sum('low_vul')),
                   'all_arachni_medium': arachni_scan_db.objects.filter(username=username,
                                                                        project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_netsparker_high': netsparker_scan_db.objects.filter(username=username,
                                                                            project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_netsparker_low': netsparker_scan_db.objects.filter(username=username,
                                                                           project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_netsparker_medium': netsparker_scan_db.objects.filter(username=username,
                                                                              project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_openvas_high': openvas_scan_db.objects.filter(username=username,
                                                                      project_id=project_id).aggregate(Sum('high_vul')),
                   'all_openvas_low': openvas_scan_db.objects.filter(username=username,
                                                                     project_id=project_id).aggregate(Sum('low_vul')),
                   'all_openvas_medium': openvas_scan_db.objects.filter(username=username,
                                                                        project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_nessus_high': nessus_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('total_high')),
                   'all_nessus_low': nessus_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('total_low')),
                   'all_nessus_medium': nessus_scan_db.objects.filter(username=username,
                                                                      project_id=project_id).aggregate(
                       Sum('total_medium')),

                   'all_dependency_high': dependencycheck_scan_db.objects.filter(username=username,
                                                                                 project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_dependency_low': dependencycheck_scan_db.objects.filter(username=username,
                                                                                project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_dependency_medium': dependencycheck_scan_db.objects.filter(username=username,
                                                                                   project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_findbugs_high': findbugs_scan_db.objects.filter(username=username,
                                                                        project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_findbugs_low': findbugs_scan_db.objects.filter(username=username,
                                                                       project_id=project_id).aggregate(Sum('low_vul')),
                   'all_findbugs_medium': findbugs_scan_db.objects.filter(username=username,
                                                                          project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_bandit_high': bandit_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_bandit_low': bandit_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_bandit_medium': bandit_scan_db.objects.filter(username=username,
                                                                      project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_clair_high': clair_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_clair_low': clair_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_clair_medium': clair_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_trivy_high': trivy_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_trivy_low': trivy_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_trivy_medium': trivy_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_gitlabsast_high': gitlabsast_scan_db.objects.filter(username=username,
                                                                            project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_gitlabsast_low': gitlabsast_scan_db.objects.filter(username=username,
                                                                           project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_gitlabsast_medium': gitlabsast_scan_db.objects.filter(username=username,
                                                                              project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_gitlabcontainerscan_high': gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                              project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_gitlabcontainerscan_low': gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                             project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_gitlabcontainerscan_medium': gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                                project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_gitlabsca_high': gitlabsca_scan_db.objects.filter(username=username,
                                                                          project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_gitlabsca_low': gitlabsca_scan_db.objects.filter(username=username,
                                                                         project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_gitlabsca_medium': gitlabsca_scan_db.objects.filter(username=username,
                                                                            project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_npmaudit_high': npmaudit_scan_db.objects.filter(username=username,
                                                                        project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_npmaudit_low': npmaudit_scan_db.objects.filter(username=username,
                                                                       project_id=project_id).aggregate(Sum('low_vul')),
                   'all_npmaudit_medium': npmaudit_scan_db.objects.filter(username=username,
                                                                          project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_nodejsscan_high': nodejsscan_scan_db.objects.filter(username=username,
                                                                            project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_nodejsscan_low': nodejsscan_scan_db.objects.filter(username=username,
                                                                           project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_nodejsscan_medium': nodejsscan_scan_db.objects.filter(username=username,
                                                                              project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_semgrepscan_high': semgrepscan_scan_db.objects.filter(username=username,
                                                                              project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_semgrepscan_low': semgrepscan_scan_db.objects.filter(username=username,
                                                                             project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_semgrepscan_medium': semgrepscan_scan_db.objects.filter(username=username,
                                                                                project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_tfsec_high': tfsec_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_tfsec_low': tfsec_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_tfsec_medium': tfsec_scan_db.objects.filter(username=username, project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_whitesource_high': whitesource_scan_db.objects.filter(username=username,
                                                                              project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_whitesource_low': whitesource_scan_db.objects.filter(username=username,
                                                                             project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_whitesource_medium': whitesource_scan_db.objects.filter(username=username,
                                                                                project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_checkmarx_high': checkmarx_scan_db.objects.filter(username=username,
                                                                          project_id=project_id).aggregate(
                       Sum('high_vul')),
                   'all_checkmarx_low': checkmarx_scan_db.objects.filter(username=username,
                                                                         project_id=project_id).aggregate(
                       Sum('low_vul')),
                   'all_checkmarx_medium': checkmarx_scan_db.objects.filter(username=username,
                                                                            project_id=project_id).aggregate(
                       Sum('medium_vul')),

                   'all_closed_vuln': scans_query.all_vuln_count_data(username, project_id, query='Closed'),
                   'all_false_positive': scans_query.all_vuln_count_data(username, project_id, query='false'),
                   'message': all_notify
                   })


def all_high_vuln(request):
    zap_all_high = ''
    arachni_all_high = ''
    webinspect_all_high = ''
    netsparker_all_high = ''
    acunetix_all_high = ''
    burp_all_high = ''
    dependencycheck_all_high = ''
    findbugs_all_high = ''
    bandit_all_high = ''
    clair_all_high = ''
    trivy_all_high = ''
    gitlabsast_all_high = ''
    gitlabcontainerscan_all_high = ''
    gitlabsca_all_high = ''
    npmaudit_all_high = ''
    nodejsscan_all_high = ''
    semgrepscan_all_high = ''
    tfsec_all_high = ''
    whitesource_all_high = ''
    checkmarx_all_high = ''
    openvas_all_high = ''
    nessus_all_high = ''

    username = request.user.username
    all_notify = Notification.objects.unread()
    if request.GET['project_id']:
        project_id = request.GET['project_id']
        severity = request.GET['severity']
    else:
        project_id = ''
        severity = ''

    if severity == 'All':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, false_positive='No')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, false_positive='No')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, false_positive='No')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, false_positive='No')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, false_positive='No')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, false_positive='No')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  false_positive='No')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, false_positive='No')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, false_positive='No')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, false_positive='No')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, false_positive='No')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, false_positive='No')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          false_positive='No')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, false_positive='No')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, false_positive='No')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, false_positive='No')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, false_positive='No')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, false_positive='No')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, false_positive='No')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, false_positive='No')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, false_positive='No')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, false_positive='No')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    elif severity == 'All_Closed':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, vuln_status='Closed')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, vuln_status='Closed')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, vuln_status='Closed')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, vuln_status='Closed')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, vuln_status='Closed')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, vuln_status='Closed')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  vuln_status='Closed')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, vuln_status='Closed')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, vuln_status='Closed')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          vuln_status='Closed')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, vuln_status='Closed')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, vuln_status='Closed')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username)


    elif severity == 'All_False_Positive':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, false_positive='Yes')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, false_positive='Yes')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, false_positive='Yes')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, false_positive='Yes')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, false_positive='Yes')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, false_positive='Yes')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  false_positive='Yes')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, false_positive='Yes')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, false_positive='Yes')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, false_positive='Yes')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, false_positive='Yes')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, false_positive='Yes')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          false_positive='Yes')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, false_positive='Yes')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, false_positive='Yes')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, false_positive='Yes')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, false_positive='Yes')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, false_positive='Yes')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, false_positive='Yes')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, false_positive='Yes')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, false_positive='Yes')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, false_positive='Yes')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    elif severity == 'Network':
        openvas_all_high = ov_scan_result_db.objects.filter(username=username, false_positive='No')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, false_positive='No')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username, pentest_type='network')

    elif severity == 'Web':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, false_positive='No')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, false_positive='No')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, false_positive='No')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, false_positive='No')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, false_positive='No')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, false_positive='No')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username, pentest_type='web')

    elif severity == 'Static':
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  false_positive='No')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, false_positive='No')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, false_positive='No')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, false_positive='No')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, false_positive='No')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, false_positive='No')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          false_positive='No')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, false_positive='No')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, false_positive='No')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, false_positive='No')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, false_positive='No')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, false_positive='No')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, false_positive='No')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, false_positive='No')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username, pentest_type='static')


    elif severity == 'High':

        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          risk='High',
                                                          false_positive='No')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 severity='High',
                                                                 false_positive='No')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity__in=[
                                                                           'Critical', 'High'],
                                                                       false_positive='No')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity='High',
                                                                       false_positive='No')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   VulnSeverity='High',
                                                                   false_positive='No')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           severity='High',
                                                           false_positive='No')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  severity='High',
                                                                                  false_positive='No')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='High',
                                                                    project_id=project_id,
                                                                    false_positive='No')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='HIGH',
                                                                project_id=project_id,
                                                                false_positive='No')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='High', project_id=project_id,
                                                              false_positive='No')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='High', project_id=project_id,
                                                              false_positive='No')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='High',
                                                                        project_id=project_id,
                                                                        false_positive='No')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          Severity='High',
                                                                                          project_id=project_id,
                                                                                          false_positive='No')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='High',
                                                                      project_id=project_id,
                                                                      false_positive='No')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='High',
                                                                    project_id=project_id,
                                                                    false_positive='No')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='High',
                                                                        project_id=project_id,
                                                                        false_positive='No')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='High',
                                                                          project_id=project_id,
                                                                          false_positive='No')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='High', project_id=project_id,
                                                              false_positive='No')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='High',
                                                                          project_id=project_id,
                                                                          false_positive='No')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='High',
                                                                      project_id=project_id,
                                                                      false_positive='No')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='High', project_id=project_id,
                                                            false_positive='No')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, risk_factor='High',
                                                                project_id=project_id,
                                                                false_positive='No')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='High',
                                                                 project_id=project_id)

    elif severity == 'Medium':

        # All Medium

        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          risk='Medium')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 severity='Medium')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity__in=[
                                                                           'Medium'])
        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity='Medium')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   VulnSeverity='Medium')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           severity='Medium')
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  severity='Medium')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='Medium',
                                                                    project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='MEDIUM',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                              project_id=project_id)

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                              project_id=project_id)

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                        project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          Severity='Medium',
                                                                                          project_id=project_id)

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                      project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                    project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                        project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                          project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='Medium',
                                                              project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                          project_id=project_id)

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                      project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='Medium', project_id=project_id)
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, risk_factor='Medium',
                                                                project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                 project_id=project_id)

    # All Minimal
    elif severity == 'Minimal':

        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          risk='Minimal')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 severity='Minimal')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity__in=[
                                                                           'Minimal'])
        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity='Minimal')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   VulnSeverity='Minimal')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           severity='Minimal')
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  severity='Minimal')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='Minimal',
                                                                    project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='MINIMAL',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='Minimal', project_id=project_id)

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='Minimal', project_id=project_id)

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='Minimal',
                                                                        project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          Severity='Minimal',
                                                                                          project_id=project_id)

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='Minimal',
                                                                      project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='Minimal',
                                                                    project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='Minimal',
                                                                        project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='Minimal',
                                                                          project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='Minimal', project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='Minimal',
                                                                          project_id=project_id)

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='Minimal',
                                                                      project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='Minimal', project_id=project_id)
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, risk_factor='Minimal',
                                                                project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Minimal',
                                                                 project_id=project_id)

    elif severity == 'Total':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          )
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 )
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       )

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       )
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   )
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id)

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id)

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id)

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id)

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id)
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, project_id=project_id)

    elif severity == 'False':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          false_positive='Yes')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 false_positive='Yes')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       false_positive='Yes')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       false_positive='Yes')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   false_positive='Yes')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           false_positive='Yes')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  false_positive='Yes')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    false_positive='Yes')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id,
                                                                                          false_positive='Yes')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                      false_positive='Yes')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    false_positive='Yes')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          false_positive='Yes')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          false_positive='Yes')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                      false_positive='Yes')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                            false_positive='Yes')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                false_positive='Yes')

        pentest_all_high = ''

    elif severity == 'Close':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          vuln_status='Closed')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 vuln_status='Closed')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Closed')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Closed')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   vuln_status='Closed')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           vuln_status='Closed')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  vuln_status='Closed')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    vuln_status='Closed')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id,
                                                                                          vuln_status='Closed')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                      vuln_status='Closed')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    vuln_status='Closed')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          vuln_status='Closed')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          vuln_status='Closed')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                      vuln_status='Closed')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                            vuln_status='Closed')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                vuln_status='Closed')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                 vuln_status='Closed')

    else:
        return HttpResponseRedirect(reverse('dashboard:proj_data' + '?project_id=%s' % project_id))

    return render(request,
                  'dashboard/all_high_vuln.html',
                  {'zap_all_high': zap_all_high,
                   'arachni_all_high': arachni_all_high,
                   'webinspect_all_high': webinspect_all_high,
                   'netsparker_all_high': netsparker_all_high,
                   'acunetix_all_high': acunetix_all_high,
                   'burp_all_high': burp_all_high,
                   'dependencycheck_all_high': dependencycheck_all_high,
                   'findbugs_all_high': findbugs_all_high,
                   'bandit_all_high': bandit_all_high,
                   'clair_all_high': clair_all_high,
                   'trivy_all_high': trivy_all_high,
                   'gitlabsast_all_high': gitlabsast_all_high,
                   'gitlabcontainerscan_all_high': gitlabcontainerscan_all_high,
                   'gitlabsca_all_high': gitlabsca_all_high,
                   'npmaudit_all_high': npmaudit_all_high,
                   'nodejsscan_all_high': nodejsscan_all_high,
                   'semgrepscan_all_high': semgrepscan_all_high,
                   'tfsec_all_high': tfsec_all_high,
                   'whitesource_all_high': whitesource_all_high,
                   'checkmarx_all_high': checkmarx_all_high,
                   'openvas_all_high': openvas_all_high,
                   'nessus_all_high': nessus_all_high,
                   'project_id': project_id,
                   'severity': severity,
                   'pentest_all_high': pentest_all_high,
                   'message': all_notify,
                   })


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        project_id = request.POST.get("project_id")
        report_type = request.POST.get("type")
        severity = request.POST.get("severity")

        resource = AllResource()

        all_data = scans_query.all_vuln_count(username=username, project_id=project_id, query=severity)

        dataset = resource.export(all_data)

        if report_type == 'csv':
            response = HttpResponse(dataset.csv, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="%s.csv"' % project_id
            return response
        if report_type == 'json':
            response = HttpResponse(dataset.json, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="%s.json"' % project_id
            return response
