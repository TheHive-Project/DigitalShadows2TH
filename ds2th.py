#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import getopt
import json
import getpass
import re

from DigitalShadows.api import DigitalShadowsApi
from thehive4py.api import TheHiveApi
from thehive4py.models import Case,CaseTask,CaseTaskLog

from config import DigitalShadows, TheHive
from ds2markdown import ds2markdown


def thSeverity(sev):

    """
        convert DigitalShadows severity in TH severity

        :sev string
    """

    severities = {
        'NONE':1,
        'VERY_LOW':1,
        'LOW':1,
        'MEDIUM':2,
        'HIGH':3
    }
    return severities[sev]



def convertDs2ThCase(content):

    """
        convert Digital Shadows incident in a TheHive Case

        :content dict object
    """

    tasks = []
    tags = ['src:DigitalShadows']
    for tag in content['tags']:
        tags.append('DS:'+tag['type']+'='+tag['name'])


    if ('summary' in content) and (len(content['summary']) > 1):
        description = content.get('summary')
    else:
        description = content.get('description', {"-"})
    case = Case(
            title="[DigitalShadows] #{} ".format(content['id']) + content['title'],
            tlp=2,
            severity=thSeverity(content['severity']),
            flag=False,
            tags=tags,
            description = description)
    return case


def caseAddTask(thapi, caseId, content):

    """
        Add task in existing case with its log
        Return the task "Imported from DigitalShadows" in the TheHive

        : caseId       Id of the case created by the import program
        : content      DigitalShadows response.content (JSON)
    """
    task = CaseTask(
                title = "Incident imported from DigitalShadows",
                description = "Incident from DigitalShadows"
                )

    m = ds2markdown(content).taskLog
    log = CaseTaskLog(message = m)
    thresponse = thapi.create_case_task(caseId, task)
    r = thresponse.json()
    thresponse = thapi.create_task_log(r['id'], log)

def import2th(thapi, response):

    """
        Convert DigitalShadows response and import it in TheHive
        Call convertDs2ThCase
        Call CaseAddTask
        Return the case fully created in TheHive

        :response  dict Response from DigitalShadows
    """

    case = convertDs2ThCase(response)
    thresponse = thapi.create_case(case)
    r = thresponse.json()
    caseAddTask(thapi, r['id'], response)


def run(argv):

    """
        Download Digital SHadows incident and create a new Case in TheHive

        :argv incident number
    """


    # get options
    incidentId = ''
    try:
        opts, args = getopt.getopt(argv, 'hi:',["incident="])
    except getopt.GetoptError:
        print(__file__ + " -i <incidentId>")
        sys.exit(2)
    for opt,arg in opts:
        if opt == '-h':
            print(__file__ + " -i <incidentNumber>")
            sys.exit()
        elif opt in ('-i','--incident'):
            incidentId = arg


    # get username and password for TheHive
    if not TheHive['username'] and not TheHive['password']:
        TheHive['username'] = input("TheHive Username [%s]: " % getpass.getuser())
        TheHive['password'] = getpass.getpass("TheHive Password: ")

    thapi = TheHiveApi(TheHive['url'],TheHive['username'],
                        TheHive['password'], TheHive['proxies'])


    # Create DigitalShadows session and get incident

    dsapi = DigitalShadowsApi(DigitalShadows)
    # response = dsapi.getIntelIncidents(incidentId, fulltext='true')
    #
    # if(response.status_code == 200):
    #     import2th(thapi, response.json())
    # elif(response.status_code == 404):
    #     response = dsapi.getIncidents(incidentId, fulltext='true')
    #     if (response.status_code == 200):
    #         import2th(thapi, response.json())
    #     else:
    #         print('ko: {}/{}'.format(response.status_code, response.text))
    #         sys.exit(0)
    # else:
    #     print('ko: {}/{}'.format(response.status_code, response.text))
    #     sys.exit(0)


    r = re.compile('S.*')
    if r.match(incidentId):
        i = incidentId[1:]
        response = dsapi.getIntelIncidents(i, fulltext='true')
        if (response.status_code == 200):
            import2th(thapi, response.json())
        else:
            print('ko: {}/{}'.format(response.status_code, response.text))
            sys.exit(0)
    else:
        response = dsapi.getIncidents(incidentId)
        if(response.status_code == 200):
            import2th(thapi, response.json())
        else:
            print('ko: {}/{}'.format(response.status_code, response.text))
            sys.exit(0)



if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -i <incidentId>")
        sys.exit(2)
