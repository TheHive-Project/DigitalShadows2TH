#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import getopt
import getpass
import datetime
from io import BytesIO
import base64

from DigitalShadows.api import DigitalShadowsApi
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

from config import DigitalShadows, TheHive
from ds2markdown import ds2markdown


def add_tags(tags, content):

    """
        add tag to tags

        :param tags is list
        :param content is list
    """
    t = tags
    for newtag in content:
        t.append("DS:{}".format(newtag))
    return t

def th_alert_tags(incident):
    tags = []
    add_tags(tags, ["id={}".format(incident.get('id')), "type={}".format(incident.get('type'))])
    for t in incident.get('tags'):
        add_tags(tags, ["{}={}".format(t.get('type'),t.get('name'))])

    return tags

def th_severity(sev):

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

def th_dataType(type):
    """
    convert DigitalShadows IOC type to TH dataType
    :param type: str
    :return: str
    """
    types = {
        'IP':'ip',
        'HOST': 'domain',
        'URL':'url',
        'SHA256':'hash',
        'SHA1':'hash',
        'MD5':'hash',
        'FILENAME':'filename',
        'FILEPATH':'filename',
        'EMAIL': 'mail'
    }

    if type in types:
        return types[type]
    else:
        return "other"

def add_alert_artefact(artefacts, dataType, data, tags, tlp):
    """

    :param artefacts: array
    :param dataType: string
    :param data: string
    :param tags: array
    :param tlp: int
    :return: array
    """

    return artefacts.append(AlertArtifact(tags=tags,
                             dataType=dataType,
                             data=data,
                             message="From DigitalShadows",
                             tlp=tlp)
                            )


def build_observables(observables):
    artefacts = []
    if observables.get('total', 0) > 0:

        for ioc in observables.get('content'):
            a = AlertArtifact(
                data=ioc.get('value'),
                dataType=th_dataType(ioc.get('type')),
                message="Observable from DigitalShadows. Source: {}".format(ioc.get('source')),
                tlp=2,
                tags=["src:DigitalShadows"]
            )
            artefacts.append(a)

    return artefacts



def build_alert(incident, observables, thumbnail):
    """
    Convert DigitalShadows alert into a TheHive Alert

    :param incident: dict
    :param observables: dict
    :param thumbnail: str
    :return: Alert object
    """

    return Alert(title="{}".format(incident.get('title')),
                 tlp=2,
                 severity=th_severity(incident.get('severity')),
                 description=ds2markdown(incident, thumbnail).thdescription,
                 type=incident.get('type'),
                 tags=th_alert_tags(incident),
                 caseTemplate=TheHive['template'],
                 source="DigitalShadows",
                 sourceRef=str(incident.get('id')),
                 artifacts=build_observables(observables)
                 )

def get_incidents(dsapi, thapi, since):
    s = (datetime.datetime.now() - datetime.timedelta(minutes=int(since))).isoformat() + 'Z'
    response = DigitalShadowsApi.find_incident(dsapi, s).json()


    for i in response.get('content'):
        alert = build_alert(i, {}, {"thumbnail":""})
        thapi.create_alert(alert)


def get_intel_incidents(dsapi, thapi, since):
    """

    :param dsapi: request to DigitalShadows
    :param thapi: reauest to TheHive
    :param since: int, number of minutes, period of time
    :return:
    """
    s = "{}/{}".format((datetime.datetime.now() - datetime.timedelta(minutes=int(since))).isoformat(),
                       datetime.datetime.now().isoformat())
    response = DigitalShadowsApi.find_intel_incident(dsapi, s).json()

    for i in response.get('content'):
        iocs = DigitalShadowsApi.get_intel_incident_iocs(dsapi, i.get('id')).json()

        if i.get('entitySummary') and i.get('entitySummary').get('screenshotThumbnailId'):
            # i.get('entitySummary')
            # i.get('entitySummary').get('screenshotThumbnailId')
            thumbnail = get_thumbnails(dsapi, i.get('entitySummary').get('screenshotThumbnailId'))
        else:
            thumbnail = {'thumbnail':''}
        alert = build_alert(i, iocs, thumbnail)

        thapi.create_alert(alert)

def get_thumbnails(dsapi, thumbnail_id):
    """
    Get Intel Incident screenshot thumbnail
    :param dsapi:
    :param thumbnail_id:
    :return: dict {base64:}
    """
    response = DigitalShadowsApi.get_intel_incident_thumbnail(dsapi,thumbnail_id)
    if response.status_code == 200:
        with BytesIO(response.content) as bytes:
            encoded = base64.b64encode(bytes.read())
            b64_thumbnail = encoded.decode()

        return {"thumbnail":"data:{};base64,{}".format(response.headers['Content-Type'], b64_thumbnail)}
    else:
        return {thumbnail: ""}

def run(argv):

    """
        Download DigitalShadows incident and create a new Case in TheHive

        :argv incident number
    """


    # get options
    try:
        opts, args = getopt.getopt(argv, 'ht:',["time="])
    except getopt.GetoptError:
        print(__file__ + " -t <time>")
        sys.exit(2)
    for opt,arg in opts:
        if opt == '-h':
            print(__file__ + " -t <time in minutes>")
            sys.exit()
        elif opt in ('-t','--time'):
            time = arg


    # get username and password for TheHive
    if not TheHive['username'] and not TheHive['password']:
        TheHive['username'] = input("TheHive Username [%s]: " % getpass.getuser())
        TheHive['password'] = getpass.getpass("TheHive Password: ")

    thapi = TheHiveApi(TheHive['url'],TheHive['username'],
                        TheHive['password'], TheHive['proxies'])


    # Create DigitalShadows session and get incidents

    dsapi = DigitalShadowsApi(DigitalShadows)
    get_incidents(dsapi,thapi,time)
    get_intel_incidents(dsapi, thapi, time)



if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -t <duration>")
        sys.exit(2)
