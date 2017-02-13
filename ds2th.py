#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import getopt
import json

from DigitalShadows.api import DigitalShadowsApi
from theHive4py.api import TheHiveApi
from theHive4py.models import Case,CaseTask,CaseTaskLog

from config import DigitalShadows, TheHive


def thSeverity(sev):
    severities = {
        'LOW':1,
        'MEDIUM':2,
        'HIGH':3
    }
    return severities[sev]

def DsCyberthreatDescription(content):
    """
        Build TheHive Case description from DS Incident
        of type CYBER-THREAT

        :content dict object
    """

    return "**scope:** " + content['scope'] + "\n\n" + \
            "**type:** " + content['type'] + "\n\n" + \
            "**occurred:** " + content['occurred'] + "\n\n" + \
            "**verified:** " + content['verified'] + "\n\n" + \
            "**modified:** " + content['modified'] + "\n\n" + \
            "**identifier:** " + str(content['id']) + "\n\n" + \
            "**Descrpition** \n\n" + content['description']


def DsInfrastructureDescription(content):
    """
        Build TheHive Case description from DS Incident
        of type CYBER-THREAT

        :content dict object
    """
    return "**scope:** " + content['scope'] + "\n\n" + \
            "**type:** " + content['type'] + "\n\n" + \
            "**occurred:** " + content['occurred'] + "\n\n" + \
            "**verified:** " + content['verified'] + "\n\n" + \
            "**publiched:** " + content['published'] + "\n\n" + \
            "**modified:** " + content['modified'] + "\n\n" + \
            "**identifier:** " + str(content['id']) + "\n\n" + \
            "**Description** \n\n " + content['description'] + "\n\n\n" + \
            "**impactDescription** \n\n " + content['impactDescription'] + "\n\n\n" + \
            "**mitigation** \n\n " + content['mitigation']




def convertDs2ThCase(content):

    """
        convert Digital Shadows incident in a TheHive Case

        :content dict object
    """

    tasks = []
    tags = ['src:DigitalShadows']
    for tag in content['tags']:
        tags.append('DS:'+tag['type']+'='+tag['name'])

        case = Case(
                title="[DigitalShadows] #{} ".format(content['id']) + content['title'],
                tlp=2,
                severity=thSeverity(content['severity']),
                flag=False,
                tags=tags,
                description = content['summary'])

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
                description = content['summary']
                )

    if content["type"] == "CYBER_THREAT":
        log = CaseTaskLog(
                    message = DsCyberthreatDescription(content)
        )

    if content["type"] == "INFRASTRUCTURE":
        log = CaseTaskLog(
                    message = DsInfrastructureDescription(content)
        )


    thresponse = thapi.create_case_task(caseId, task)
    r = json.loads(thresponse.content)
    thresponse = thapi.create_task_log(r['id'],log)

def import2th(thapi, response):

    """
        Convert DigitalShadows response and import it in TheHive
        Call convertDs2ThCase
        Call CaseAddTask
        Return the case fully created in TheHive

        :response   Response from DigitalShadows
    """

    case = convertDs2ThCase(json.loads(response.content))
    thresponse = thapi.create_case(case)
    r = json.loads(thresponse.content)
    caseAddTask(thapi, r['id'], json.loads(response.content))


def run(argv):

    """
        Download Digital SHadows incident and create a new Case in TheHive

        :argv incident number
    """

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


    dsapi = DigitalShadowsApi(DigitalShadows)
    thapi = TheHiveApi(TheHive['url'],TheHive['username'],TheHive['password'])

    response = dsapi.getIntelIncidents(incidentId, fulltext='true')

    if(response.status_code == 200):
        # case = convertDs2Th(json.loads(response.content))
        import2th(thapi, response)
    elif(response.status_code == 404):
        response = dsapi.getIncidents(incidentId, fulltext='true')
        import2th(thapi, response)
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)



if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -i <incidentId>")
        sys.exit(2)
