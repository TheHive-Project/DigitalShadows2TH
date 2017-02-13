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


class DSDescription():

    def __init__(self, content):

        self.log =  "**Scope:** " + content['scope'] + "\n\n" + \
                    "**Type:** " + content['type'] + "\n\n" + \
                    "**Occurred:** " + content.get('occurred',"-") + "\n\n" + \
                    "**Verified:** " + content.get('verified',"-") + "\n\n" + \
                    "**Modified:** " + content.get('modified',"-") + "\n\n" + \
                    "**Publiched:** " + content.get('published',"-") + "\n\n" + \
                    "**Identifier:** " + str(content['id']) + "\n\n" + \
                    "**Tags:** " + self.tags(content) + "\n\n" + \
                    "**Description** \n\n" + content['description'] + "\n\n" + \
                    self.entitySummary(content)


    def entitySummary(self, content):
        if 'entitySummary' in content:
            source ="----" + "\n\n" + \
                    "**Source Information** \n\n" + \
                    "**Source:** " + content['entitySummary']['source'] + "\n\n" + \
                    "**Domain:** " + content['entitySummary']['domain'] + "\n\n" + \
                    "**Date:** " + content['entitySummary']['sourceDate'] + "\n\n" + \
                    "**Type:** " + content['entitySummary']['type'] + "\n\n"



            if 'summaryText' in content['entitySummary']:
                summaryText = content['entitySummary']['summaryText']
                source += "**Source data** \n\n" + \
                        "> " + summaryText + "\n\n"

            if 'dataBreach' in content['entitySummary']:
                dataBreach = content['entitySummary']['dataBreach']
                source += "\n\n" + "----\n\n" + \
                            "**Target** \n\n" + \
                            "**Title: " + dataBreach['title'] + "**\n\n" + \
                            "**Target domain:** " + dataBreach['domainName'] + "\n\n" + \
                            "**Published:** " + dataBreach['published'] + "\n\n" + \
                            "**Occured:** " + dataBreach['occured'] + "\n\n" + \
                            "**Modified:** " + dataBreach['modified'] + "\n\n" + \
                            "**Id:** " + dataBreach['id'] + "\n\n"

            return source

        def IpAddressEntity(self,content):
            if 'IpAddressEntity' in content:
                source = "\n\n" + "----\n\n" + \
                        "**Source Information** \n\n" + \
                        "**Source:** " + content['IpAddressEntity']['source'] + "\n\n" + \
                        "**Domain:** " + content['IpAddressEntity']['domain'] + "\n\n" + \
                        "**Date:** " + content['IpAddressEntity']['sourceDate'] + "\n\n" + \
                        "**Type:** " + content['IpAddressEntity']['type'] + "\n\n" + \
                        "**Summary:** " + content['IpAddressEntity']['summaryText'] + "\n\n" + \


            return source



    def lci(self, content):
        if content["linkedContentIncidents"] not in []:
            linkedContentIncidents = ""
            for lci in content["linkedContentIncidents"]:
                linkedContentIncidents += "- {} \n\n".format(lci)
        else:
            linkedContentIncidents = "-"
        return linkedContentIncidents


    def tags(self, content):
        if 'tags' in content:
            t = ""
            for tag in content['tags']:
                t += "_{}_, ".format(tag['name'])
        else:
            t += "-"
        return t


def thSeverity(sev):
    severities = {
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

        if 'summary' in content:
            description = content.get('summary')
        else:
            description = content.get('description', {})
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
    print("task created \n")

    if content["type"] == "CYBER_THREAT":
        m = DSDescription(content).log
        log = CaseTaskLog(message = m)



    if content["type"] == "INFRASTRUCTURE":
        m = DSDescription(content).log
        print(m)
        log = CaseTaskLog(message = m)


    thresponse = thapi.create_case_task(caseId, task)
    r = json.loads(thresponse.content)
    thresponse = thapi.create_task_log(r['id'], log)

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
