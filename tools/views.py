from __future__ import unicode_literals
from tools.models import sslscan_result_db, nikto_result_db, nmap_result_db, nmap_scan_db, \
    nikto_vuln_db, dirsearch_result_db, dirsearch_scan_db, openvas_result_db, openvas_scan_db, \
    sniper_config_db, sniper_result_db, sniper_scan_db, audit_question_db, audit_db, audit_question_group_db#, audit_answer_db
from networkscanners.models import openvas_scan_db, ov_scan_result_db, task_schedule_db, serversetting
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
import json
from django.http import HttpResponse
from django.http import JsonResponse

# NOTE[gmedian]: in order to be more portable we just import everything rather than add anything in this very script
from tools.nmap_vulners.nmap_vulners_view import nmap_vulners, nmap_vulners_port, nmap_vulners_scan

sslscan_output = None
nikto_output = ''
scan_result = ''
all_nmap = ''

def audit_comment_save(request):
    client_id = request.GET.get('client_id')
    question_id = request.GET.get('question_id')
    comment = request.GET.get('comment')
    if comment and client_id and question_id:
        audit_db.objects.filter(client_id=client_id, question_id=question_id).update(
            comment=comment
        )

    response = {
        'comment': comment
    }
    return JsonResponse(response)

def audit_scripts(request):
    # Fix: minor bug it loads the first client on the dropdown answer
    username = request.user.username
    all_clients = client_db.objects.filter(username=username)
    all_groups = audit_question_group_db.objects.all
    all_questions = audit_question_db.objects.all

    if request.method == 'POST':
        client_id = request.POST.get('client_id')
    elif request.method == 'GET':
        client_id = request.GET.get("client_id")

    if client_id:
        all_audits = audit_db.objects.filter(client_id=client_id)
        cli_name = client_db.objects.filter(username=username, client_id=client_id)
        address = audit_db.objects.filter(client_id=client_id).order_by('-date_time')[0]
        accept = audit_db.objects.filter(client_id=client_id).order_by('-date_time')[0]

        return render(request, 'audit_scripts.html', {'all_clients': all_clients,
                                                    'all_groups': all_groups,
                                                    'all_questions': all_questions,
                                                    'all_audits': all_audits,
                                                    'client_name': cli_name[0].client_name,
                                                    'client_id': cli_name[0].client_id,
                                                    'address': address.address,
                                                    'accept': accept.accept})
    else:
        return render(request, 'audit_scripts.html', {'all_clients': all_clients,
                                                    'all_groups': all_groups,
                                                    'all_questions': all_questions})

def edit_group_save(request):
    if request.method == 'POST':
        client_id = request.POST.get('client_id')
        question_group = request.POST.get('question_group')
        question_group_id = request.POST.get('question_group_id')

        audit_question_group_db.objects.filter(question_group_id=question_group_id).update(
            question_group=question_group,
        )

        return HttpResponseRedirect("/tools/audit_scripts/?client_id=%s" % client_id)

def edit_audit_save(request):
    if request.method == 'POST':
        client_id = request.POST.get('client_id')
        question = request.POST.get('question')
        question_id = request.POST.get('question_id')

        audit_question_db.objects.filter(question_id=question_id).update(
            question=question,
        )

        return HttpResponseRedirect("/tools/audit_scripts/?client_id=%s" % client_id)

def edit_group(request):
    question_group_id = request.GET.get('question_group_id')
    client_id = request.GET.get("client_id")
    print(client_id, question_group_id)
    all_groups = audit_question_group_db.objects.filter(question_group_id=question_group_id)

    return render(request, 'edit_group.html', {'all_groups': all_groups,
                                               'client_id': client_id})

def edit_audit(request):
    question_id = request.GET.get('question_id')
    client_id = request.GET.get("client_id")
    print(client_id, question_id)
    all_questions = audit_question_db.objects.filter(question_id=question_id)

    return render(request, 'edit_audit.html', {'all_questions': all_questions,
                                               'client_id': client_id})

def audit_list(request):
    username = request.user.username
    all_clients = client_db.objects.filter(username=username)
    all_questions = audit_question_db.objects.all
    all_clients_audits = []
    for client in all_clients:
        all_audits = audit_db.objects.filter(client_id=client.client_id)
        all_clients_audits.append(all_audits)

    return render(request, 'audit_list.html', { 'all_clients': all_clients,
                                                'all_clients_audits': all_clients_audits,
                                                'all_questions': all_questions})

def audit_scripts_save(request):
    client_id = request.GET.get('client_id')
    question_id = request.GET.get('question_id')
    answer = request.GET.get('answer')
    if answer and client_id and question_id:
        audit_db.objects.filter(client_id=client_id, question_id=question_id).update(
            answer=answer
        )
    all_audits = audit_db.objects.filter(client_id=client_id)
    addressed = 0
    for audit in all_audits:
        if audit.answer == "" or audit.answer == None or audit.answer == "Not Implemented":
            addressed = addressed + 0
        elif audit.answer == "Implemented on Some Systems":
            addressed = addressed + .33
        elif audit.answer == "Implemented on All Systems":
            addressed = addressed + .66
        elif audit.answer == "Implemented & Automated on All Systems":
            addressed = addressed + 1
    x = 100 / len(all_audits)
    multiply = addressed * x
    divide = multiply / 100
    accepted = 1 - divide
    address = "{:.0%}".format(divide)
    accept = "{:.0%}".format(accepted)
    date_time = datetime.now()
    audit_db.objects.filter(client_id=client_id).update(
            flag="old"
        )
    audit_db.objects.filter(client_id=client_id, question_id=question_id).update(
            date_time=date_time,
            address=address,
            accept=accept,
            flag="new"
        )

    response = {
        'address': address,
        'accept': accept
    }
    return JsonResponse(response)

def add_audit_del(request):
    if request.method == 'GET':
        client_id = request.GET.get("client_id")
        question_group_id = request.GET.get("question_group_id")

        # dump_scan = audit_db.objects.filter(question_group_id=question_group_id)
        # dump_scan.delete()

        # dump_scan = audit_question_db.objects.filter(question_group_id=question_group_id)
        # dump_scan.delete()

        dump_scan = audit_question_group_db.objects.filter(question_group_id=question_group_id)
        dump_scan.delete()

        # Note: minor bug doesn't return directly to client audit script page
        return HttpResponseRedirect("/tools/audit_scripts/?client_id=%s" % client_id)

def audit_scripts_del(request):
    if request.method == 'GET':
        client_id = request.GET.get("client_id")
        question_id = request.GET.get("question_id")

        dump_scan = audit_db.objects.filter(question_id=question_id)
        dump_scan.delete()

        dump_scan = audit_question_db.objects.filter(question_id=question_id)
        dump_scan.delete()

        return HttpResponseRedirect("/tools/audit_scripts/?client_id=%s" % client_id)

def add_group(request):
    username = request.user.username
    all_clients = client_db.objects.filter(username=username)

    return render(request, 'add_group.html', {'all_clients': all_clients})

def add_group_save(request):
    if request.method == 'POST':
        question_group = request.POST.get('question_group')
        date_time = datetime.now()
        question_group_id = uuid.uuid4()

        dump_scan = audit_question_group_db(
            date_time=date_time,
            question_group=question_group,
            question_group_id=question_group_id
        )
        dump_scan.save()

        return HttpResponseRedirect(reverse('tools:add_audit'))

def add_audit(request):
    all_groups = audit_question_group_db.objects.all

    return render(request, 'add_audit.html', {'all_groups': all_groups})

def add_audit_save(request):
    if request.method == 'POST':
        question = request.POST.get('question')
        question_group_id = request.POST.get('question_group_id')
        date_time = datetime.now()
        question_id = uuid.uuid4()

        dump_scan = audit_question_db(
            date_time=date_time,
            question=question,
            question_id=question_id,
            question_group_id=question_group_id
        )
        dump_scan.save()

        all_clients = client_db.objects.all()

        for client in all_clients:
            audit_client = audit_db(client_id = client.client_id,
                                    client_name = client.client_name,
                                    question_id = question_id,
                                    question_group_id = question_group_id,
                                    answer = "",
                                    answer_color = "",
                                    date_time = date_time,
                                    address = "",
                                    accept = ""
                                    )
            audit_client.save()

        return HttpResponseRedirect(reverse('tools:audit_scripts'))

def sniper_vuln_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        vuln_id = request.POST.get("id")
        scan_id = request.POST.get("scan_id")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            _vuln_id = value_split.__getitem__(i)
            delete_vuln = sniper_result_db.objects.filter(username=username, vuln_id=_vuln_id)
            delete_vuln.delete()

        return HttpResponseRedirect("/tools/sniper_list/?scan_id=%s" % scan_id)


def sniper_scan_del(request):
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

            del_scan = sniper_result_db.objects.filter(username=username, scan_id=_scan_id)
            del_scan.delete()
            del_scan = sniper_scan_db.objects.filter(username=username, scan_id=_scan_id)
            del_scan.delete()
            sniper_config_db.objects.filter(last_scan_id=_scan_id).update(
                                last_scan_id = "")

    return HttpResponseRedirect('/tools/sniper_summary/')

def sniper_summary(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        # Choose a project
        project_id = request.POST.get('proj_id', )
        all_sniper_scan = sniper_scan_db.objects.filter(username=username, project_id=project_id)
        proj_name = project_db.objects.filter(username=username, project_id=project_id)
    else:
        all_sniper_scan = sniper_scan_db.objects.filter(username=username)
        proj_name = project_db.objects.filter(username=username)
    all_projects = project_db.objects.filter(username=username)

    return render(request,
                'sniper_summary.html',
                {'all_sniper': all_sniper_scan,
                 'proj_name': proj_name[0].project_name,
                 'all_projects': all_projects,}
                )

def sniper_list(request):
    username = request.user.username
    scan_id = request.GET.get('scan_id', )
    all_sniper = sniper_result_db.objects.filter(username=username, scan_id=scan_id)
    if all_sniper:
        ip_address = all_sniper[0].ip_address
    else:
        ip_address = ""

    return render(request,
                  'sniper_list.html',
                  {'all_sniper': all_sniper,
                   'ip': ip_address}
                  )

def sniper_result1(request):
    username = request.user.username
    scan_id = request.GET.get('scan_id', )
    all_sniper = sniper_scan_db.objects.filter(username=username, scan_id=scan_id)
    if all_sniper:
        file_name = all_sniper[0].result1
        file = all_sniper[0].result_file1
    else:
        file_name = ""
        file = ""

    return render(request,
                  'sniper_result.html',
                  {'file_name': file_name,
                   'file': file}
                  )

def sniper_result2(request):
    username = request.user.username
    scan_id = request.GET.get('scan_id', )
    all_sniper = sniper_scan_db.objects.filter(username=username, scan_id=scan_id)
    if all_sniper:
        file_name = all_sniper[0].result2
        file = all_sniper[0].result_file2
    else:
        file_name = ""
        file = ""

    return render(request,
                  'sniper_result.html',
                  {'file_name': file_name,
                   'file': file}
                  )
                
def sniper_log(request):
    username = request.user.username
    scan_id = request.GET.get('scan_id', )
    all_sniper = sniper_scan_db.objects.filter(username=username, scan_id=scan_id)
    if all_sniper:
        file_name = all_sniper[0].log
        file = all_sniper[0].log_file
    else:
        file_name = ""
        file = ""

    return render(request,
                  'sniper_result.html',
                  {'file_name': file_name,
                   'file': file}
                  )

def sniper_delete(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        config_id = request.POST.get('config_id')
        del_config = sniper_config_db.objects.filter(username=username, config_id=config_id)
        del_config.delete()

    return HttpResponseRedirect(reverse('networkscanners:sniper'))

def sniper_launch(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    config_id = request.GET.get('config_id', )
    project_id = request.GET.get('project_id', )
    all_config = sniper_config_db.objects.filter(username=username, config_id=config_id)

    try:
        print('Start Sniper scan')
        sniper = "./scripts/" + str(all_config[0].script)
        
        if all_config[0].option2:
            ip = str(all_config[0].ip_address)
            ip_ranges = ip.split(".")
            ip_range = ip_ranges[0] + "." + ip_ranges[1] + "." + ip_ranges[2] + "." + "0/24"
            subprocess.run(
                [sniper, all_config[0].ip_address, ip_range]
            )
        elif all_config[0].option1:
            subprocess.run(
                [sniper, all_config[0].ip_address]
            )
        else:
            subprocess.run(
                [sniper]
            )

        print('Completed Sniper scan')

    except Exception as e:
        print('Error in Sniper scan:', e)

    def sniper_parse(all_config, sniper_file, date_time, scan_id, config_id, project_id):
        with open(sniper_file, 'r') as f:
            files = f.readlines()
            for fi in files:
                fil = fi.replace("'", "")
                file = fil.replace("|", "")
                f = file.replace("=", "")
                if f != None or f != "":
                    dump_data = sniper_result_db(
                        username=username,
                        vuln_id = uuid.uuid4(),
                        project_id=project_id,
                        config_id=config_id,
                        ip_address=all_config[0].ip_address,
                        date_time=date_time,
                        scan_id = scan_id,
                        result=sniper_file,
                        output=f,
                    )
                    dump_data.save()

    try:
        print('Start Parsing Sniper')
        date_time = datetime.now()
        scan_id = uuid.uuid4()
        sniper_file = str(all_config[0].result1)
        sniper_parse(all_config, sniper_file, date_time, scan_id, config_id, project_id)
        with open(sniper_file, 'r') as f:
            result_file1 = f.read()

        sniper_file2 = str(all_config[0].result2)
        if sniper_file2:
            sniper_parse(all_config, sniper_file2, date_time, scan_id, config_id, project_id)
            with open(sniper_file2, 'r') as f:
                result_file2 = f.read()
        else:
            result_file2 = ""

        all_sniper_result = sniper_result_db.objects.filter(username=username, scan_id=scan_id)
        log_file = str(all_config[0].log1)
        with open(log_file, 'r') as f:
            log_files = f.read()

        dump_data = sniper_scan_db(
            username=username,
            project_id=project_id,
            config_name=all_config[0].config_name,
            config_id=config_id,
            total_sniper=len(all_sniper_result),
            ip_address=all_config[0].ip_address,
            date_time=date_time,
            scan_id=scan_id,
            log_file=log_files,
            result_file1=result_file1,
            result_file2=result_file2,
            log=log_file,
            result1=sniper_file,
            result2=sniper_file2,
        )
        dump_data.save()

        sniper_config_db.objects.filter(config_id=config_id).update(
                                last_scan_id = scan_id)

        print("Finish parsing and saving...")

        # return HttpResponseRedirect("/tools/sniper_list/?scan_id=%s" % scan_id)
        return HttpResponse(scan_id)

    except Exception as e:
        print('Error in Sniper parser:', e)

    return HttpResponseRedirect(reverse('networkscanners:sniper'))

def sniper_edit(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET': 
        config_id = request.GET.get('config_id', )
        all_config = sniper_config_db.objects.filter(username=username, config_id=config_id)
        all_proj = project_db.objects.filter(username=username)
        project = project_db.objects.filter(project_id=all_config[0].project_id)
        if project:
            proj_name = project[0].project_name
        else:
            proj_name = ""
        
        return render(request, 'sniper_edit.html', {'all_proj': all_proj,
                                                    'proj_name' : proj_name,
                                                    'all_config': all_config,
                                                        })

    # Save Edit
    if request.method == 'POST':
        config_name = request.POST.get('config_name')
        ip_address = request.POST.get('ip_address')
        script = request.POST.get('script')
        option1 = request.POST.get('option1')
        option2 = request.POST.get('option2')
        log1 = request.POST.get('log1')
        log2 = request.POST.get('log2')
        result1 = request.POST.get('result1')
        result2 = request.POST.get('result2')
        config_id = request.POST.get('config_id', )
        project_id = request.POST.get('project_id', )
        sniper_config_db.objects.filter(config_id=config_id).update(
                                config_name = config_name,
                                ip_address = ip_address,
                                script = script,
                                option1 = option1,
                                option2 = option2,
                                log1 = log1,
                                log2 = log2,
                                result1 = result1,
                                result2 = result2,
                                project_id = project_id)

        return HttpResponseRedirect(reverse('networkscanners:sniper'))

def sniper_add(request):

    username = request.user.username
    config_id = request.GET.get('config_id', )
    all_config = sniper_config_db.objects.filter(username=username, config_id=config_id)
    all_proj = project_db.objects.filter(username=username)

    # Save Add
    if request.method == 'POST':
        config_name = request.POST.get('config_name')
        ip_address = request.POST.get('ip_address')
        script = request.POST.get('script')
        option1 = request.POST.get('option1')
        option2 = request.POST.get('option2')
        log1 = request.POST.get('log1')
        log2 = request.POST.get('log2')
        result1 = request.POST.get('result1')
        result2 = request.POST.get('result2')
        project_id = request.POST.get('project_id', )
        config_id = uuid.uuid4()
        date_time = datetime.now()

        dump_sniper = sniper_config_db(
            username = username,
            config_id = config_id,
            config_name = config_name,
            ip_address = ip_address,
            script = script,
            option1 = option1,
            option2 = option2,
            log1 = log1,
            log2 = log2,
            result1 = result1,
            result2 = result2,
            date_time=date_time,
            project_id = project_id,
        )
        dump_sniper.save()
        return HttpResponseRedirect(reverse('networkscanners:sniper'))

    return render(request,
                  'sniper_add.html',
                  {'all_proj': all_proj,
                  'all_config': all_config}
                  )

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
        with open('dirsearch.json', 'r') as f:
            data = json.load(f)
            for key, value in data.items():
                if key != 'time':
                    for row in value:
                        dump_data = dirsearch_result_db(
                            username=username,
                            project_id=project_id,
                            scan_id=scan_id,
                            ip_address=ip_address,
                            date_time=date_time,
                            url=row['path'],
                            status=row['status'],
                            size=row['content-length'],
                            redirection=row['redirect'],
                        )
                        dump_data.save()
        f.close()
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
                reruns.append('--json-report=dirsearch.json')
                subprocess.run(reruns)
                parse_ds(username, project_id, scan_id, ip_address)
            else:
                print(ip_address)
                subprocess.run(
                    ['python3', '/opt/dirsearch/dirsearch.py', '-u', ip_address, '-e', 'html,php,txt', '-x', '400,403,404,503', '-w', 'ds_wordlist.txt', '--json-report=dirsearch.json']
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

        return HttpResponse(scan_id)

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
        scan_id = request.GET.get('scan_id',)
        scan_url = request.GET.get('scan_url',)
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
        scan_id = request.POST.get('scan_id')

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()

        for i in range(0, split_length):
            _scan_id = value_split.__getitem__(i)
            print(_scan_id)

            del_scan = nmap_scan_db.objects.filter(username=username, scan_id=_scan_id)
            del_scan.delete()
            del_scan = nmap_result_db.objects.filter(username=username, scan_id=_scan_id)
            del_scan.delete()

        return HttpResponseRedirect("/manual_scan/scan_list/")

def nmap_vuln_del(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get('id')
        print(scan_id)

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()

        for i in range(0, split_length):
            _scan_id = value_split.__getitem__(i)

            del_scan = nmap_result_db.objects.filter(username=username, id=_scan_id)
            ip = del_scan[0].ip_address
            del_scan.delete()

        return HttpResponseRedirect("/tools/nmap/?ip=%s" % ip)