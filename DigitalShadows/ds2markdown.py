#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import json

class ds2markdown():

    def __init__(self, content):

        self.source =""

        self.report =  "**Scope:** " + content['scope'] + "\n\n" + \
                    "**Type:** " + content['type'] + "\n\n" + \
                    "**Occurred:** " + content.get('occurred',"-") + "\n\n" + \
                    "**Verified:** " + content.get('verified',"-") + "\n\n" + \
                    "**Modified:** " + content.get('modified',"-") + "\n\n" + \
                    "**Publiched:** " + content.get('published',"-") + "\n\n" + \
                    "**Identifier:** " + str(content['id']) + "\n\n" + \
                    "**Tags:** " + self.tags(content) + "\n\n" + \
                    "----\n\n" + \
                    "#### Description ####  \n\n" + content['description'] + "\n\n" + \
                    self.impactDescription(content) + "\n\n" + \
                    self.mitigation(content) + "\n\n" + \
                    self.entitySummary(content)


    def entitySummary(self, content):
        source = ""
        if 'entitySummary' in content:
            c = content['entitySummary']
            source += self.Summary(c)

            if 'summaryText' in c:
                summaryText = c['summaryText']
                source += "#### Source data #### \n\n" + \
                        "```\n" + summaryText + "\n```\n\n"


        if 'IpAddressEntitySummary' in content:
            c = content['IpAddressEntity']
            source = self.Summary(c)

            if 'IpAddressDetails' in c:
                details = c['IpAddressDetails']
                source += "\n\n" + "----\n\n" + \
                        "#### IP address details #### \n\n" + \
                        "**IP:** " + details['ipAddress'] + "\n\n" + \
                        "**AS:** " + details['autonomousSystemNumber'] + "\n\n" + \
                        "**Reverse Domain Name:** " + details['reverseDomainName'] + "\n\n" + \
                        "**Service Provider:** " + details['serviceProvider'] + "\n\n"
                if 'location' in details:
                    source += "**Geolocalication:** " + details['location']['country'] + \
                                +"/"+ details['location']['city'] + "\n\n"

            if 'ports' in  c:
                port = c['ports']
                source += "\n\n" + "----\n\n" + \
                        " #### Port details #### \n\n" + \
                        "**Port:** " + port['portNumber'] + "/" + port['transport'] + "\n\n" + \
                        "**Scanned on:** " + port['scannedOn'] + "\n\n" + \
                        "**Device Type:** " + port['deviceType'] + "\n\n" + \
                        "**Banner:** " + port['banner'] + "\n\n"

            if 'vulnerability' in  c:
                vuln = c['vulnerability']
                source += "#### vulnerability Information ####  \n\n" + \
                        "**CVE ID:** " + vuln['specification']['specification']['cveId'] + "\n\n" + \
                        "**CVE description:** " + vuln['specification']['specification']['description'] + "\n\n" + \
                        "**Severity:** " + vuln['specification']['specification']['severity'] + "\n\n" + \
                        "**Mitigation:** " + vuln['specification']['specification']['mitigation']+ "\n\n"

        if 'MessageEntitySummary' in content:
            c = content['MessageEntitySummary']
            source += self.Summary(c)

            if 'conversationFragment' in c:
                conv = c['conversationFragment']
                source += "#### Conversation Information #### \n\n" + \
                        "**Server:** " + conv['server'] + "\n\n" + \
                        "**Channel:** " + conv['channel'] + "\n\n"
                if "Message" in conv:
                    msg = conv["Message"]
                    source += "**Message**\n\n" + \
                            "**User:** " + "\"{0}\" - {1}\n\n".format(msg['nickname'],msg['username']) + \
                            "**Sent:** " + msg['sent'] + "\n\n"  + \
                            "**Message**\n\n" + \
                            "```\n\n" + msg['content'] + "\n\n```"

        return source


    def Summary(self, content):
        source = ""
        source += "----\n\n" + \
                "#### Source Information #### \n\n" + \
                "**Source:** " + content['source'] + "\n\n" + \
                "**Domain:** " + content['domain'] + "\n\n" + \
                "**Date:** " + content['sourceDate'] + "\n\n" + \
                "**Type:** " + content['type'] + "\n\n"

        if 'dataBreach' in content:
            print("ok")
            dataBreach = content['entitySummary']['dataBreach']
            source += "**Databreach target** \n\n" + \
                        "**Title: " + dataBreach['title'] + "**\n\n" + \
                        "**Target domain:** " + dataBreach['domainName'] + "\n\n" + \
                        "**Published:** " + dataBreach['published'] + "\n\n" + \
                        "**Occured:** " + dataBreach['occured'] + "\n\n" + \
                        "**Modified:** " + dataBreach['modified'] + "\n\n" + \
                        "**Id:** " + dataBreach['id'] + "\n\n"
        return source


    def impactDescription(self, content):
        impact = ""
        if "impactDescription" in content:
            impact = "\n\n#### Impact Description #### \n\n" + \
                    content.get('impactDescription', "-")
        return impact

    def mitigation(self, content):
        mitigation = ""
        if "mitigation" in content:
            mitigation = "\n\n#### Mitigation #### \n\n" + \
                    content.get('mitigation', "-")
        return mitigation


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
