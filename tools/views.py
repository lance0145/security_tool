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
from tools.models import sslscan_result_db, nikto_result_db, nmap_result_db, nmap_scan_db, nikto_vuln_db, dirsearch_result_db, dirsearch_scan_db, openvas_result_db, openvas_scan_db
from networkscanners.models import openvas_scan_db, \
    ov_scan_result_db, \
    task_schedule_db, serversetting
from django.shortcuts import render, HttpResponseRedirect
import subprocess
import defusedxml.ElementTree as ET
from scanners.scanner_parser.network_scanner import nmap_parser, OpenVas_Parser
import uuid
import codecs
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
import hashlib
import os
import sys
import csv
from datetime import datetime
from notifications.signals import notify
from django.urls import reverse
from django.core import signing
from projects.models import project_db, client_db

# NOTE[gmedian]: in order to be more portable we just import everything rather than add anything in this very script
from tools.nmap_vulners.nmap_vulners_view import nmap_vulners, nmap_vulners_port, nmap_vulners_scan

sslscan_output = None
nikto_output = ''
scan_result = ''
all_nmap = ''

def openvas(request):

    username = request.user.username
    all_openvas = openvas_scan_db.objects.filter(username=username)#, scan_id=scan_id)
    ip_address = request.GET.get('ip', )

    if request.method == 'GET' and ip_address:
        all_openvas = openvas_result_db.objects.filter(username=username, ip_address=ip_address)
    
    if request.method == 'POST':
        ip_address = request.POST.get('ip')
        project_id = request.POST.get('project_id')
        command = request.POST.get('command')
        scan_id = uuid.uuid4()
        ss = serversetting.objects.filter(username=username).last()
        user_ip = str(signing.loads(ss.server_username)) + "@" + str(ss.server_ip)
        password = str(signing.loads(ss.server_password))

        try:
            print('Start OpenVas scan')
            if command:
                cmd = 'export jailbreak="yes";' + str(command)
            else:
                cmd = 'export jailbreak="yes";openvas ' + str(ip_address)
            #root@10.254.10.45
            subprocess.run(
                ['sshpass', '-p', password, 'ssh', '-t', user_ip, cmd, ';exit;/bin/bash']
            )
            report = 'Report_for_' + str(ip_address) + ".xml"
            #remote = 'root@10.254.10.45:/root/' + report
            remote = user_ip + ':/root/' + report
            destination = os.getcwd() + '/openvas/' + report
            subprocess.run(
                ['scp', remote, destination]
            )
            subprocess.run(
                ['sed', '-i', '/<report id="/,$!d', destination]
            )
            print('Completed OpenVas scan')
        except Exception as e:
            print('Error in OpenVas scan:', e)

        try:
            date_time = datetime.now()
            scan_status = "100"
            tree = ET.parse(destination)
            root_xml = tree.getroot()
            # tree = ET.fromstring(destination)
            # notags = ET.tostring(tree, encoding='utf8', method='text')
            hosts = OpenVas_Parser.get_hosts(root_xml)
            for host in hosts:
                scan_dump = openvas_scan_db(scan_ip=host,
                                         scan_id=host,
                                         date_time=date_time,
                                         project_id=project_id,
                                         scan_status=scan_status,
                                         username=username
                                         )
                scan_dump.save()
            OpenVas_Parser.updated_xml_parser(project_id=project_id,
                                              scan_id=scan_id,
                                              root=root_xml,
                                              username=username
                                              )
        except Exception as e:
            print('Error in xml parser:', e)

        return HttpResponseRedirect('/tools/openvas/')

    return render(request,
                  'openvas_summary.html',
                  {'all_openvas': all_openvas,
                   'ip': ip_address}

                  )

def openvas_summary(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        project_id = request.POST.get('proj_id', )
        all_openvas = openvas_scan_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id) 
    else:
        all_openvas = openvas_scan_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                  'openvas_summary.html',
                  {'all_openvas': all_openvas,
                  'proj_name': proj_name[0].project_name,
                  'all_projects': all_projects,}
                  )

def dirsearch_scan(request):
    def parse_ds(username, project_id, scan_id, ip_address):
        date_time = datetime.now()
        with open('dirsearch.csv', 'r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                print(username, project_id, scan_id, ip_address, row['Time'])
                dump_data = dirsearch_result_db(
                    username=username,
                    project_id=project_id,
                    scan_id=scan_id,
                    ip_address=ip_address,
                    date_time=row['Time'],
                    url=row['URL'],
                    status=row['Status'],
                    size=row['Size'],
                    redirection=row['Redirection'],
                )
                dump_data.save()
        csv_file.close()

        all_dir = dirsearch_result_db.objects.filter(scan_id=scan_id)
        dump_data = dirsearch_scan_db(
            username=username,
            project_id=project_id,
            scan_id=scan_id,
            total_dirs=len(all_dir),
            ip_address=ip_address,
            date_time=date_time,
        )
        dump_data.save()
        print("Finish parsing and saving...")


    username = request.user.username
    all_dirs = dirsearch_scan_db.objects.filter(username=username)#, scan_id=scan_id)
    ip_address = request.GET.get('ip', )

    if request.method == 'POST':    
        ip_address = request.POST.get('ip')
        project_id = request.POST.get('project_id')
        command = request.POST.get('command')
        scan_id = uuid.uuid4()

        try:
            print('Start dirsearch scan')
            if command:
                reruns = command.split()
                reruns.append('--csv-report=dirsearch.csv')
                subprocess.run(reruns)
                parse_ds(username, project_id, scan_id, ip_address)
            else:
                print(ip_address)
                subprocess.run(
                    ['./dirsearch', '-u', ip_address, '-e', 'html,php,txt', '-x', '400,403,404,503', '-w', 'ds_wordlist.txt', '--csv-report=dirsearch.csv']
                )
                parse_ds(username, project_id, scan_id, ip_address)
            print('Completed dirsearch scan')
        except Exception as e:
            print('Error in dirsearch scan:', e)

        return HttpResponseRedirect('/tools/dirsearch_scan/')

    return render(request,
                  'dirsearch_summary.html',
                  {'all_dirs': all_dirs,}
                    # 'ip': ip_address}

                  )

def dirsearch_summary(request):
    """
    :param request:
    :return:
    """
    # TODO check further this why it is directing here rather than dirseach_summary
    username = request.user.username
    if request.method == 'POST':
        project_id = request.POST.get('proj_id', )
        all_dirs = dirsearch_scan_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id) 
    else:
        all_dirs = dirsearch_scan_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                  'dirsearch_summary.html',
                  {'all_dirs': all_dirs,
                  'proj_name': proj_name[0].project_name,
                  'all_projects': all_projects,}
                  )

def dirsearch_list(request):
    username = request.user.username
    ip_address = request.GET.get('ip', )
    all_dirs = dirsearch_result_db.objects.filter(username=username, ip_address=ip_address)
    return render(request,
                  'dirsearch_list.html',
                  {'all_dirs': all_dirs,
                   'ip': ip_address}
                  )

def dirsearch_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        del_scan = dirsearch_scan_db.objects.filter(username=username, scan_id=scan_id)
        del_scan.delete()

    return HttpResponseRedirect('/tools/dirsearch_summary/')

def dirsearch_delete(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        id = request.POST.get('id')
        del_scan = dirsearch_result_db.objects.filter(username=username, id=id)
        ip = del_scan[0].ip_address
        del_scan.delete()

    return HttpResponseRedirect("/tools/dirsearch_list/?ip=%s" % ip)


def sslscan(request):
    """

    :return:
    """
    username = request.user.username
    global sslscan_output
    all_sslscan = sslscan_result_db.objects.filter(username=username)

    user = request.user

    if request.method == 'POST':
        scan_url = request.POST.get('scan_url')
        project_id = request.POST.get('project_id')

        scan_item = str(scan_url)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = uuid.uuid4()
            scan_url = value_split.__getitem__(i)

            try:
                sslscan_output = subprocess.check_output(['sslscan', '--no-colour', scan_url])
                notify.send(user, recipient=user, verb='SSLScan Completed')

            except Exception as e:
                print(e)

            dump_scans = sslscan_result_db(scan_url=scan_url,
                                           scan_id=scan_id,
                                           project_id=project_id,
                                           sslscan_output=sslscan_output,
                                           username=username,
                                           )

            dump_scans.save()
            return HttpResponseRedirect(reverse('tools:sslscan'))

    return render(request,
                  'sslscan_list.html',
                  {'all_sslscan': all_sslscan}

                  )


def sslscan_result(request):
    """

    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scan_result = sslscan_result_db.objects.filter(username=username, scan_id=scan_id)

    return render(request,
                  'sslscan_result.html',
                  {'scan_result': scan_result}
                  )


def sslcan_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = sslscan_result_db.objects.filter(username=username, scan_id=vuln_id)
            del_scan.delete()

    return HttpResponseRedirect('/tools/sslscan/')

def nikto(request):
    """

    :return:
    """
    username = request.user.username
    global nikto_output
    all_nikto = nikto_result_db.objects.filter(username=username)

    user = request.user

    if request.method == 'POST':
        ip = request.POST.get('ip')
        project_id = request.POST.get('project_id')

        # scan_item = str(scan_url)
        # value = scan_item.replace(" ", "")
        # value_split = value.split(',')
        # split_length = value_split.__len__()s
        # for i in range(0, split_length):
        date_time = datetime.now()
        scan_id = uuid.uuid4()

        nikto_res_path = 'nikto/' + str(scan_id) + '.html'
        os.makedirs(os.path.dirname(nikto_res_path), 0o777, True)

        command = request.POST.get('command')

        if command:
            reruns = command.split()
            reruns.append('-o')
            reruns.append(nikto_res_path)
            nikto_output = subprocess.run(reruns)
            print(nikto_output)
            f = codecs.open(nikto_res_path, 'r')
            data = f.read()
            try:
                nikto_html_parser(data, project_id, scan_id, username)
            except Exception as e:
                print(e)
        else:
            try:

                nikto_output = subprocess.check_output(['nikto', '-o', nikto_res_path,
                                                        '-Format', 'htm', '-Tuning', '123bde',
                                                        '-host', ip])
                print(nikto_output)
                f = codecs.open(nikto_res_path, 'r')
                data = f.read()
                try:
                    nikto_html_parser(data, project_id, scan_id, username)
                except Exception as e:
                    print(e)

            except Exception as e:
                print(e)

                try:
                    print("New command running......")
                    print(ip)
                    nikto_output = subprocess.check_output(['nikto', '-o', nikto_res_path,
                                                            '-Format', 'htm', '-Tuning', '123bde',
                                                            '-host', ip])
                    print(nikto_output)
                    f = codecs.open(nikto_res_path, 'r')
                    data = f.read()
                    try:
                        nikto_html_parser(data, project_id, scan_id, username)
                        notify.send(user, recipient=user, verb='Nikto Scan Completed')
                    except Exception as e:
                        print(e)


                except Exception as e:
                    print(e)

            dump_scans = nikto_result_db(scan_url=ip,
                                         scan_id=scan_id,
                                         project_id=project_id,
                                         date_time=date_time,
                                         nikto_scan_output=nikto_output,
                                         username=username,
                                         )

            dump_scans.save()

    return render(request,
                  'nikto_scan_list.html',
                  {'all_nikto': all_nikto}

                  )

def nikto_result(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        project_id = request.POST.get('proj_id', )
        all_nikto = nikto_result_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id) 
    else:
        all_nikto = nikto_result_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                  'nikto_scan_list.html',
                  {'all_nikto': all_nikto,
                  'proj_name': proj_name[0].project_name,
                  'all_projects': all_projects,}
                  )


def nikto_result_vul(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        # scan_url = request.GET.get('scan_url',)
        # print(scan_url)

    if request.method == "POST":
        false_positive = request.POST.get('false')
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        nikto_vuln_db.objects.filter(username=username, vuln_id=vuln_id,
                                     scan_id=scan_id).update(false_positive=false_positive, vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = nikto_vuln_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                discription = vi.discription
                hostname = vi.hostname
                dup_data = discription + hostname
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                nikto_vuln_db.objects.filter(username=username, vuln_id=vuln_id,
                                             scan_id=scan_id).update(false_positive=false_positive,
                                                                     vuln_status=status,
                                                                     false_positive_hash=false_positive_hash
                                                                     )
    scan_result = nikto_vuln_db.objects.filter(username=username, scan_id=scan_id)

    vuln_data = nikto_vuln_db.objects.filter(username=username, scan_id=scan_id,
                                             false_positive='No',
                                             )

    vuln_data_close = nikto_vuln_db.objects.filter(username=username, scan_id=scan_id,
                                                   false_positive='No',
                                                   vuln_status='Closed'
                                                   )

    false_data = nikto_vuln_db.objects.filter(username=username, scan_id=scan_id,
                                              false_positive='Yes')

    return render(request,
                  'nikto_vuln_list.html',
                  {'scan_result': scan_result,
                   'vuln_data': vuln_data,
                   'vuln_data_close': vuln_data_close,
                   'false_data': false_data,
                #    'scan_url': scan_url
                   }
                  )


def nikto_vuln_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln")
        scan_id = request.POST.get("scan_id")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            _vuln_id = value_split.__getitem__(i)
            delete_vuln = nikto_vuln_db.objects.filter(username=username, vuln_id=_vuln_id)
            delete_vuln.delete()

        return HttpResponseRedirect("/tools/nikto_result_vul/?scan_id=%s" % scan_id)


def nikto_scan_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()

        for i in range(0, split_length):
            _scan_id = value_split.__getitem__(i)

            del_scan = nikto_result_db.objects.filter(username=username, scan_id=_scan_id)
            del_scan.delete()
            del_scan = nikto_vuln_db.objects.filter(username=username, scan_id=_scan_id)
            del_scan.delete()

    return HttpResponseRedirect('/tools/nikto/')


def nmap_scan(request):
    """

    :return:
    """
    username = request.user.username
    all_nmap = nmap_scan_db.objects.filter(username=username)

    return render(request,
                  'nmap_scan.html',
                  {'all_nmap': all_nmap}

                  )


def nmap(request):
    """

    :return:
    """
    global all_nmap
    username = request.user.username

    if request.method == 'GET':
        ip_address = request.GET['ip']

        all_nmap = nmap_result_db.objects.filter(username=username, ip_address=ip_address)
    if request.method == 'POST':    
        ip_address = request.POST.get('ip')
        project_id = request.POST.get('project_id')
        command = request.POST.get('command')
        scan_id = uuid.uuid4()

        try:
            print('Start Nmap scan')
            if command:
                reruns = command.split()
                reruns.append('-oX')
                reruns.append('nmap.xml')
                subprocess.run(reruns)
            else:
                subprocess.check_output(
                    ['nmap', '-v', '-sV', '-Pn', '-p', '1-65535', ip_address, '-oX', 'nmap.xml']
                )

            print('Completed nmap scan')

        except Exception as e:
            print('Error in nmap scan:', e)

        try:
            tree = ET.parse('nmap.xml')
            root_xml = tree.getroot()

            nmap_parser.xml_parser(root=root_xml,
                                   scan_id=scan_id,
                                   project_id=project_id,
                                   username=username
                                   )

        except Exception as e:
            print('Error in xml parser:', e)

        return HttpResponseRedirect('/tools/nmap_scan/')

    return render(request,
                  'nmap_list.html',
                  {'all_nmap': all_nmap,
                   'ip': ip_address}

                  )


def nmap_result(request):
    """

    :param request:
    :return:
    """
    global scan_result
    username = request.user.username

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scan_result = nmap_result_db.objects.filter(username=username, scan_id=scan_id)

    return render(request,
                  'nmap_scan_result.html',
                  {'scan_result': scan_result}
                  )


def nmap_scan_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get('scn_id')
        del_scan = nmap_scan_db.objects.filter(username=username, scan_id=scan_id)
        del_scan.delete()
        # ip_address = request.POST.get('ip_address')

        # scan_item = str(ip_address)
        # value = scan_item.replace(" ", "")
        # value_split = value.split(',')
        # split_length = value_split.__len__()

        # for i in range(0, split_length):
        #     vuln_id = value_split.__getitem__(i)

        #     del_scan = nmap_result_db.objects.filter(username=username, ip_address=vuln_id)
        #     del_scan.delete()
        #     del_scan = nmap_scan_db.objects.filter(username=username, scan_ip=vuln_id)
        #     del_scan.delete()

    return HttpResponseRedirect('/manual_scan/scan_list/')

def nmap_del(request):
    username = request.user.username
    if request.method == 'POST':
        id = request.POST.get('id')
        del_scan = nmap_result_db.objects.filter(username=username, id=id)
        ip = del_scan[0].ip_address
        del_scan.delete()

    return HttpResponseRedirect("/tools/nmap/?ip=%s" % ip)
