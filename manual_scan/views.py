# -*- coding: utf-8 -*-
# Copyright (C) 20210125 Allan Abendanio
#
# Email:   lance0145@gmail.com
#
# This file is part of Afovos Project.

""" Author: Anand Tiwari """

from __future__ import unicode_literals
import uuid
from manual_scan.models import manual_scan_results_db, manual_scans_db
from tools.models import nmap_scan_db
from datetime import datetime
from projects.models import project_db, client_db
from manual_scan.models import VulnerabilityData
import uuid
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from .forms import *
from django.http import JsonResponse


def scan_list(request):
    username = request.user.username
    if request.method == 'POST':
        project_id = request.POST.get('proj_id', )
        all_nmap = nmap_scan_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id)
    else:
        all_nmap = nmap_scan_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                  'scan_list.html',
                  {'all_nmap': all_nmap,
                  'proj_name': proj_name[0].project_name,
                  'all_projects': all_projects,}

                  )

def ajax_vuln(request):
    username = request.user.username
    vuln_id = request.GET.get('id')
    status = request.GET.get('status')
    date_time = datetime.now()
    if vuln_id and status:
        edit_status = manual_scan_results_db.objects.filter(username=username, vuln_id=vuln_id).update(
            vuln_status=status,
            date_time=date_time,
        )

    response = {
        'status': status
    }
    return JsonResponse(response)

def list_scan(request):
    username = request.user.username
    if request.method == 'POST':
        project_id = request.POST.get('proj_id', )
        all_scans = manual_scans_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id)
    else:
        all_scans = manual_scans_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                  'list_scan.html',
                  {'all_projects': all_projects,
                   'proj_name': proj_name[0].project_name,
                   'all_scans': all_scans}
                  )

def list_scan_auto(request):
    username = request.user.username
    if request.method == 'POST':
        project_id = request.POST.get('proj_id', )
        all_scans = manual_scans_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id)
    else:
        all_scans = manual_scans_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                  'list_scan_auto.html',
                  {'all_projects': all_projects,
                   'proj_name': proj_name[0].project_name,
                   'all_scans': all_scans}
                  )

def add_list_scan(request):
    username = request.user.username
    all_projects = project_db.objects.filter(username=username)
    all_clients = client_db.objects.filter(username=username)

    if request.method == 'POST':
        scan_url = request.POST.get('scan_url')
        project_id = request.POST.get('project_id')
        pentest_type = request.POST.get('pentest_type')
        date_time = datetime.now()
        scanid = uuid.uuid4()
        client_id = request.POST.get('client_id')

        dump_scan = manual_scans_db(
            date_time=date_time,
            scan_url=scan_url,
            scan_id=scanid,
            pentest_type=pentest_type,
            project_id=project_id,
            username=username,
            client_id=client_id,
        )
        dump_scan.save()
        return HttpResponseRedirect(reverse('manual_scan:list_scan'))

    return render(request,
                  'add_list_scan.html',
                  {'all_projects': all_projects,
                  'all_clients': all_clients}
                  )


def vuln_list(request):
    """

    :param request:
    :return:
    """
    username = request.user.username

    vuln_data = VulnerabilityData.objects.filter(username=username)

    for vul in vuln_data:
        vuln_id = vul.vuln_data_id

    if request.method == 'GET':
        client_id = request.GET.get('client_id', )
        project_id = request.GET.get('project_id', )
        all_vuln = manual_scan_results_db.objects.filter(username=username, client_id=client_id)#.order_by('severity')
        scan_url = manual_scans_db.objects.filter(client_id=client_id)
        scan = ""
        if scan_url:
            scan = scan_url[0].scan_url

    return render(request,
                  'manual_vuln_list.html',
                  {'all_vuln': all_vuln,
                   'client_id': client_id,
                   'vuln_data': vuln_id,
                   'project_id': project_id,
                   'scan_url': scan
                   }
                  )


# Adding a new vulnerability finding into database
def add_vuln(request):
    """

    :param request:
    :return:
    """
    scanid = None
    severity_color = None
    project_id = None
    client_id = None
    username = request.user.username

    if request.method == 'GET':
        vuln_name = request.GET.get('name', )
        vuln_id = request.GET.get('vul_id', )
        severity = request.GET.get('severity', )
        vuln_url = request.GET.get('instance', )
        description = request.GET.get('description', )
        solution = request.GET.get('solution', )
        reference = request.GET.get('reference', )
        scan_id = request.GET.get('scan_id', )
        project_id = request.GET.get('project_id')
        pentest_type = request.GET.get('pentest_type')
        date_time = datetime.now()
        # risk_rating = request.GET.get('risk_rating')
        # likelihood = request.GET.get('likelihood')
        # consequence = request.GET.get('consequence')
        get_client_id = project_db.objects.filter(project_id=project_id)
        client_id = get_client_id[0].client_id
        # client_id = request.GET.get('client_id')

        if severity == "Critical":
            severity_color = "danger"

        elif severity == "High":
            severity_color = "danger"

        elif severity == 'Medium':
            severity_color = "warning"

        elif severity == 'Minimal':
            severity_color = "info"

        elif severity == 'Very Minimal':
            severity_color = "info"

        dump_data = manual_scan_results_db(
            vuln_id=vuln_id,
            vuln_name=vuln_name,
            severity_color=severity_color,
            severity=severity,
            vuln_url=vuln_url,
            description=description,
            solution=solution,
            reference=reference,
            scan_id=scan_id,
            pentest_type=pentest_type,
            vuln_status='Open',
            project_id=project_id,
            username=username,
            # risk_rating = risk_rating,
            # likelihood = likelihood,
            # consequence = consequence,
            client_id = client_id,
        )
        dump_data.save()

        all_scan_data = manual_scan_results_db.objects.filter(username=username)

        total_vuln = len(all_scan_data)
        total_critical =  len(all_scan_data.filter(severity="Critical"))
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Minimal"))
        total_very_low = len(all_scan_data.filter(severity="Very Minimal"))

        manual_scans_db.objects.filter(username=username, project_id=project_id, client_id=client_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            critical_vul =total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            very_low_vul = total_very_low,
            username=username,
        )

        return HttpResponseRedirect(reverse('networkscanners:vul_details') + '?scan_id=%s' % (scan_id))

    if request.method == 'POST':
        vuln_name = request.POST.get('vuln_name')
        severity = request.POST.get('vuln_severity')
        vuln_url = request.POST.get('vuln_instance')
        description = request.POST.get('vuln_description')
        solution = request.POST.get('vuln_solution')
        reference = request.POST.get('vuln_reference')
        scan_id = request.POST.get('scan_id')
        project_id = request.POST.get('project_id')
        pentest_type = request.POST.get('pentest_type')
        date_time = datetime.now()
        vuln_id = uuid.uuid4()
        risk_rating = request.POST.get('risk_rating')
        likelihood = request.POST.get('likelihood')
        consequence = request.POST.get('consequence')
        client_id = request.POST.get('client_id')

        if severity == "Critical":
            severity_color = "danger"

        elif severity == "High":
            severity_color = "danger"

        elif severity == 'Medium':
            severity_color = "warning"

        elif severity == 'Minimal':
            severity_color = "info"

        elif severity == 'Very Minimal':
            severity_color = "info"


        dump_data = manual_scan_results_db(
            vuln_id=vuln_id,
            vuln_name=vuln_name,
            severity_color=severity_color,
            severity=severity,
            vuln_url=vuln_url,
            description=description,
            solution=solution,
            reference=reference,
            scan_id=scan_id,
            pentest_type=pentest_type,
            vuln_status='Open',
            project_id=project_id,
            username=username,
            risk_rating = risk_rating,
            likelihood = likelihood,
            consequence = consequence,
            client_id = client_id,
        )
        dump_data.save()

        all_scan_data = manual_scan_results_db.objects.filter(username=username)

        total_vuln = len(all_scan_data)
        total_critical =  len(all_scan_data.filter(severity="Critical"))
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Minimal"))
        total_very_low = len(all_scan_data.filter(severity="Very Minimal"))

        manual_scans_db.objects.filter(username=username, project_id=project_id, client_id=client_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            critical_vul =total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            very_low_vul = total_very_low,
            username=username,
        )

        # sk: changing functionality so that it goes back to vuln list after adding a vuln
        #
        return HttpResponseRedirect(reverse('manual_scan:vuln_list') + '?scan_id=%s&project_id=%s&client_id=%s' % (scan_id, project_id, client_id))

    return render(request, 'add_manual_vuln.html', {'scanid': scanid})


def vuln_details(request):
    """

    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']

        vuln_detail = manual_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)

    return render(request, 'manual_vuln_data.html', {'vuln_detail': vuln_detail})


def edit_vuln(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    scanid = None
    severity_color = None
    project_id = None
    client_id = None

    if request.method == 'GET':
        vuln_id= request.GET.get('vuln_id', )
        project_id= request.GET.get('project_id', )
        client_id = request.GET.get('client_id', )
        vuln_data = manual_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)

        return render(request, 'edit_vuln.html',
                    {'vuln_data': vuln_data,
                    'vuln_id': vuln_id,
                    'project_id': project_id,
                    'client_id': client_id
                    })

    if request.method == 'POST':
        vuln_id = request.POST.get('vuln_id')
        project_id = request.POST.get('project_id')
        client_id = request.POST.get('client_id')
        vuln_name = request.POST.get('vuln_name')
        severity = request.POST.get('vuln_severity')
        vuln_url = request.POST.get('vuln_instance')
        description = request.POST.get('vuln_description')
        solution = request.POST.get('vuln_solution')
        reference = request.POST.get('vuln_reference')
        scan_id = request.POST.get('scan_id')
        date_time = datetime.now()
        risk_rating = request.POST.get('risk_rating')
        likelihood = request.POST.get('likelihood')
        consequence = request.POST.get('consequence')

        if severity == "Critical":
            severity_color = "danger"

        elif severity == "High":
            severity_color = "danger"

        elif severity == 'Medium':
            severity_color = "warning"

        elif severity == 'Minimal':
            severity_color = "info"

        elif severity == 'Very Minimal':
            severity_color = "info"

        manual_scan_results_db.objects.filter(username=username, vuln_id=vuln_id).update(
            vuln_name=vuln_name,
            severity=severity,
            vuln_url=vuln_url,
            description=description,
            solution=solution,
            reference=reference,
            severity_color=severity_color,
            risk_rating = risk_rating,
            likelihood = likelihood,
            consequence = consequence,
        )
        all_scan_data = manual_scan_results_db.objects.filter(username=username, project_id=project_id, client_id=client_id)

        total_vuln = len(all_scan_data)
        total_critical =  len(all_scan_data.filter(severity="Critical"))
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Minimal"))
        total_very_low = len(all_scan_data.filter(severity="Very Minimal"))

        manual_scans_db.objects.filter(username=username, project_id=project_id, client_id=client_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            critical_vul =total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            very_low_vul = total_very_low,
            username=username,
        )
        return HttpResponseRedirect(
            reverse('manual_scan:vuln_list') + '?client_id=%s&project_id=%s' % (client_id, project_id))


def manual_vuln_data(request):
    username = request.user.username

    if request.method == 'POST':
        vuln_id = request.POST.get('vuln_id')
        status = request.POST.get('status')
        scan_id = request.POST.get('scan_id')
        project_id = request.POST.get('project_id')
        date_time = datetime.now()

        manual_scan_results_db.objects.filter(username=username, vuln_id=vuln_id).update(
            vuln_status=status,
            date_time=date_time,
        )
        all_scan_data = manual_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_status='Open')

        total_vuln = len(all_scan_data)
        total_critical =  len(all_scan_data.filter(severity="Critical"))
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Minimal"))
        total_very_low = len(all_scan_data.filter(severity="Very Minimal"))

        manual_scans_db.objects.filter(username=username, scan_id=scan_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            critical_vul =total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            very_low_vul = total_very_low,
            username=username,
        )

    return HttpResponseRedirect(
        reverse('manual_scan:vuln_list') + '?scan_id=%(scan_id)s&project_id=%(project_id)s' % {'scan_id': scan_id,
                                                                                               'project_id': project_id})


def del_vuln(request):
    """

    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        get_vuln_id = request.POST.get('vuln_id')
        project_id = request.POST.get('project_id')
        client_id = request.POST.get('client_id')

        scan_item = str(get_vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()

        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            del_vuln = manual_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            del_vuln.delete()

        all_scan_data = manual_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vuln = len(all_scan_data)
        total_critical =  len(all_scan_data.filter(severity="Critical"))
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Minimal"))
        total_very_low = len(all_scan_data.filter(severity="Very Minimal"))

        manual_scans_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vul=total_vuln,
            critical_vul =total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            very_low_vul = total_very_low,
            username=username,
        )
        
        return HttpResponseRedirect(
            reverse('manual_scan:vuln_list') + '?client_id=%s&project_id=%s' % (client_id, project_id))


def del_scan(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        get_scan_id = request.POST.get('scan_id')

        scan_item = str(get_scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            del_scan = manual_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            del_scan.delete()

            del_scan_info = manual_scans_db.objects.filter(username=username, scan_id=scan_id)
            del_scan_info.delete()

        all_scan_data = manual_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vuln = len(all_scan_data)
        total_critical =  len(all_scan_data.filter(severity="Critical"))
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Minimal"))
        total_very_low = len(all_scan_data.filter(severity="Very Minimal"))

        manual_scans_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vul=total_vuln,
            critical_vul =total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            very_low_vul = total_very_low,
            username=username,
        )

        return HttpResponseRedirect(reverse('manual_scan:list_scan'))


def add_vuln_data(request):
    """

    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        vuln_data_id = uuid.uuid4()
        vuln_name = request.POST.get('vuln_name')
        vuln_description = request.POST.get('vuln_description')
        vuln_severity = request.POST.get('vuln_severity')
        vuln_remediation = request.POST.get('vuln_remediation')
        vuln_references = request.POST.get('vuln_references')

        dump_data = VulnerabilityData(
            vuln_data_id=vuln_data_id,
            vuln_name=vuln_name,
            vuln_description=vuln_description,
            vuln_severity=vuln_severity,
            vuln_remediation=vuln_remediation,
            vuln_references=vuln_references,
            username=username,
        )
        dump_data.save()

        return HttpResponseRedirect(reverse('manual_scan:list_scan'))
        # return render(request, 'manual_vuln_list.html', {'all_vuln': all_vuln, 'scan_id': scan_id, 'vuln_data': vuln_id, 'project_id': project_id } )

    return render(request, 'manual_vuln_data.html')


# Add Vulnerability from list or select to add
def add_new_vuln(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_vuln_data = VulnerabilityData.objects.filter(username=username)
    if request.method == 'GET':
        scan_id = request.GET.get('scan_id', )
        vuln_id= request.GET.get('vuln_id', )
        project_id= request.GET.get('project_id', )
        client_id = request.GET.get('client_id', )

        all_vuln = manual_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        vuln_data = VulnerabilityData.objects.filter(username=username, vuln_data_id=vuln_id)

        # print(all_vuln)
    return render(request,
                  'add_vulnerability.html',
                  {
                      'all_vuln': all_vuln,
                      'vuln_data': vuln_data,
                      'all_vuln_data': all_vuln_data,
                      'scan_id': scan_id,
                      'project_id': project_id,
                      'client_id': client_id,
                  }
                  )
