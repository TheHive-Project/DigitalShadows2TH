#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import getopt
import getpass
import datetime
from io import BytesIO
import base64
import logging


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
        'HIGH':3,
        'VERY_HIGH':3
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

    a = Alert(title="{}".format(incident.get('title')),
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
    return a

def get_incidents(dsapi, since):
    """
    :param dsapi: request to DigitalShadows
    :param since: int, number of minutes, period of time
    :return: list of TheHive alerts
    """
    s = "{}/{}".format((datetime.datetime.utcnow() - datetime.timedelta(minutes=int(since))).isoformat(),
                       datetime.datetime.utcnow().isoformat())
    response = dsapi.find_incidents(s)

    if response.get('status') == "success":
        data = response.get('json')
        logging.debug('DigitalShadows: {}  incidents(s) downloaded'.format(data.get('total')))

        for i in data.get('content'):
            if i.get('entitySummary') and i.get('entitySummary').get('screenshotThumbnailId'):
                thumbnail = build_thumbnail(dsapi, i.get('entitySummary').get('screenshotThumbnailId'))
            else:
                thumbnail = {'thumbnail':""}
            yield build_alert(i, {}, thumbnail)
    else:
        logging.debug("Error while fetching incident #{}: {}".format(id, response.get('json')))
        sys.exit("Error while fetching incident #{}: {}".format(id, response.get('json')))

def get_incident(dsapi, id):
    """
    :param dsapi: DigitalShadows api init
    :param id: incident id
    :return: TheHive alert
    """
    response = dsapi.get_incident(id)
    if response.get('status') == 'success':
        data = response.get('json')
        if data.get('entitySummary') and data.get('entitySummary').get('screenshotThumbnailId'):
            thumbnail = build_thumbnail(dsapi, data.get('entitySummary').get('screenshotThumbnailId'))
        else:
            thumbnail = {'thumbnail': ""}
        yield build_alert(data, {}, thumbnail)
    else:
        logging.debug("Error while fetching incident #{}: {}".format(id, response.get('json')))
        sys.exit("Error while fetching incident #{}: {}".format(id, response.get('json')))


def get_intel_incidents(dsapi, since):
    """

    :param dsapi: request to DigitalShadows
    :param since: int, number of minutes, period of time
    :return: alert
    """
    s = "{}/{}".format((datetime.datetime.utcnow() - datetime.timedelta(minutes=int(since))).isoformat(),
                       datetime.datetime.utcnow().isoformat())
    response = dsapi.find_intel_incidents(s)

    if response.get('status') == "success":
        data = response.get('json')
        logging.debug('DigitalShadows: {} intel incidents(s) downloaded'.format(data.get('total')))

        for i in data.get('content'):
            logging.debug('Intel-incident number: {}'.format(i.get('id')))
            iocs = dsapi.get_intel_incident_iocs(i.get('id')).json()

            if i.get('entitySummary') and i.get('entitySummary').get('screenshotThumbnailId'):
                thumbnail = build_thumbnail(dsapi, i.get('entitySummary').get('screenshotThumbnailId'))
            else:
                thumbnail = {'thumbnail':''}
            yield build_alert(i, iocs, thumbnail)

    else:
        logging.debug("Error while searching intel-incidents since {} min: {}".format(s, response.get('json')))
        sys.exit("Error while searching intel-incidents since {} min: {}".format(s, response.get('json')))

def get_intel_incident(dsapi, id):
    """
    :param dsapi: DigitalShadows api init
    :param id: intel-incident id
    :return: Thehive alert
    """
    response = dsapi.get_intel_incident(id)
    if response.get('status') == "success":
        json = response.get('json')
        if json.get('entitySummary') and json.get('entitySummary').get('screenshotThumbnailId'):
            thumbnail = build_thumbnail(dsapi, json.get('entitySummary').get('screenshotThumbnailId'))
        else:
            thumbnail = {'thumbnail': ""}
        iocs = dsapi.get_intel_incident_iocs(json.get('id')).json()
        yield build_alert(json, iocs, thumbnail)
    else:
        logging.debug("Error while fetching intel-incident #{}: {}".format(id, response.get('json')))
        sys.exit("Error while fetching intel-incident #{}: {}".format(id, response.get('json')))


def build_thumbnail(dsapi, thumbnail_id):
    """
    Get Intel Incident screenshot thumbnail
    :param dsapi:
    :param thumbnail_id:
    :return: dict with base64 pict ready to be added in markdown
    """
    response = DigitalShadowsApi.get_thumbnail(dsapi,thumbnail_id)
    if response.status_code == 200:
        with BytesIO(response.content) as bytes:
            encoded = base64.b64encode(bytes.read())
            b64_thumbnail = encoded.decode()

        return {"thumbnail":"data:{};base64,{}".format(response.headers['Content-Type'], b64_thumbnail)}
    else:
        return {"thumbnail": ""}

def create_thehive_alerts(config, alerts):
    """
    :param TheHive: TheHive config
    :param alerts: List of alerts
    :return:
    """
    # if len(alerts) > 0:

    thapi = TheHiveApi(config.get('url', None), config.get('key'), config.get('password', None),
                       config.get('proxies'))
    for a in alerts:
        thapi.create_alert(a)


def run(argv):

    """
        Download DigitalShadows incident and create a new Case in TheHive
        :argv (options, log, since, intel, incident)
    """


    # get options
    try:
        opts, args = getopt.getopt(argv, 'lhs:I:i:',["log=","since=", "intel=", "incident="])
    except getopt.GetoptError:
        print(__file__ + " -s <time>")
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-l', '--log'):
            logging.basicConfig(filename='{}/ds2th.log'.format(os.path.dirname(os.path.realpath(__file__))),
                                level=arg, format='%(asctime)s %(levelname)s %(message)s')
            logging.debug('logging enabled')

    for opt,arg in opts:
        if opt == '-h':
            print(__file__ + " -s <time in minutes>")
            sys.exit()
        elif opt in ('-s','--since'):
            since = arg
            logging.info('ds2th.py started')
            # init DigitalShadows api
            dsapi = DigitalShadowsApi(DigitalShadows)
            # get Intel incidents and create alert
            intel = get_intel_incidents(dsapi, since)
            create_thehive_alerts(TheHive, intel)
            # get incidents and create alerts
            incidents = get_incidents(dsapi, since)
            create_thehive_alerts(TheHive, incidents)

        elif opt in ('-I', '--intel'):
            # init DigitalShadows api
            dsapi = DigitalShadowsApi(DigitalShadows)
            # Get Intel-incident from id
            alerts = get_intel_incident(dsapi, int(arg))
            # create alerts
            create_thehive_alerts(TheHive, alerts)

        elif opt in ('-i', '--incident'):
            # init DigitalShadows api
            dsapi = DigitalShadowsApi(DigitalShadows)
            # Get incident from id
            alerts = get_incident(dsapi, int(arg))
            # create alerts
            create_thehive_alerts(TheHive, alerts)


if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -s <since last time in minutes>")
        sys.exit(2)
