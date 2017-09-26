#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import getopt
import argparse
import datetime
from io import BytesIO
import base64
import logging


from DigitalShadows.api import DigitalShadowsApi
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

from config import DigitalShadows, TheHive
from ds2markdown import ds2markdown


class monitoring():
    
    def __init__(self, file, freq):
        self.monitoring_file = file
        self.freq = freq

    def start(self):
        """
        delete and create a new monitoring_file
        :return: 
        """
        if not os.path.isfile(self.monitoring_file):
            f = open(self.monitoring_file, 'a')
            f.close()
        else:
            if datetime.datetime.utcfromtimestamp((os.stat(self.monitoring_file).st_birthtime)) > \
                                ( datetime.datetime.utcnow() - datetime.timedelta(minutes=self.freq)):
                logging.debug("Monitoring: ellapsed time without running: {} -> {}".format(
                    datetime.datetime.fromtimestamp(os.stat(self.monitoring_file).st_birthtime).isoformat(),
                    datetime.datetime.now().isoformat()))
            
            os.remove(self.monitoring_file)
            f = open(self.monitoring_file,'a')
            f.close()


    def finish(self):
        """
        Append 'SUCCESS' in monitoring_file
        :return:
        """
        
        try:
            f = open(self.monitoring_file, 'a')
            f.write("SUCCESS")
            f.close()
        except (IOError, OSError) as e:
            logging.debug("Monitoring:  file error: {}".format(e))
            sys.exit(1)


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

        :param sev: string
        :type sev: string
        :return value
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
    logging.debug("build_alert: alert built for DS id #{}".format(incident.get('id')))
    return a

def find_incidents(dsapi, since):
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
        logging.debug('find_incidents(): {} DS incident(s) downloaded'.format(data.get('total')))

        for i in data.get('content'):
            if i.get('entitySummary') and i.get('entitySummary').get('screenshotThumbnailId'):
                thumbnail = build_thumbnail(dsapi, i.get('entitySummary').get('screenshotThumbnailId'))
            else:
                thumbnail = {'thumbnail':""}
            yield build_alert(i, {}, thumbnail)
    else:
        logging.debug("find_incidents(): Error while fetching incident #{}: {}".format(id, response.get('json')))
        sys.exit("find_incidents(): Error while fetching incident #{}: {}".format(id, response.get('json')))

def get_incidents(dsapi, id_list):
    """
    :param dsapi: DigitalShadows api init
    :param id: incident id
    :type id: list
    :return: TheHive alert
    """
    while id_list:
        id = id_list.pop()
        response = dsapi.get_incident(id)
        if response.get('status') == 'success':
            data = response.get('json')
            logging.debug('get_incidents(): DS incident {} fetched'.format(data.get('id')))
            if data.get('entitySummary') and data.get('entitySummary').get('screenshotThumbnailId'):
                thumbnail = build_thumbnail(dsapi, data.get('entitySummary').get('screenshotThumbnailId'))
            else:
                thumbnail = {'thumbnail': ""}
            yield build_alert(data, {}, thumbnail)
        else:
            logging.debug("get_incidents(): Error while fetching incident #{}: {}".format(id, response.get('json')))
            sys.exit("find_incidents: Error while fetching incident #{}: {}".format(id, response.get('json')))


def find_intel_incidents(dsapi, since):
    """
    :param dsapi: request to DigitalShadows
    :param since: number of minutes, period of time
    :type since: int
    :return: alert
    """
    s = "{}/{}".format((datetime.datetime.utcnow() - datetime.timedelta(minutes=int(since))).isoformat(),
                       datetime.datetime.utcnow().isoformat())
    response = dsapi.find_intel_incidents(s)

    if response.get('status') == "success":
        data = response.get('json')
        logging.debug('find_intel_incidents(): {} DS intel-incident(s) downloaded'.format(data.get('total')))

        for i in data.get('content'):
            iocs = dsapi.get_intel_incident_iocs(i.get('id')).json()

            if i.get('entitySummary') and i.get('entitySummary').get('screenshotThumbnailId'):
                thumbnail = build_thumbnail(dsapi, i.get('entitySummary').get('screenshotThumbnailId'))
            else:
                thumbnail = {'thumbnail':''}
            yield build_alert(i, iocs, thumbnail)

    else:
        logging.debug("find_intel_incidents(): Error while searching intel-incidents since {} min: {}".format(s, response.get('json')))
        sys.exit("find_intel_incidents(): Error while searching intel-incidents since {} min: {}".format(s, response.get('json')))

def get_intel_incidents(dsapi, id_list):
    """
    :param dsapi: DigitalShadows api init
    :param id: intel-incident id
    :type id: list
    :return: Thehive alert
    """
    while id_list:  
        id = id_list.pop()
        response = dsapi.get_intel_incident(id)
        if response.get('status') == "success":
            data = response.get('json')
            logging.debug('get_incidents(): DS intel-incident {} fetched'.format(data.get('id')))
            if data.get('entitySummary') and data.get('entitySummary').get('screenshotThumbnailId'):
                thumbnail = build_thumbnail(dsapi, data.get('entitySummary').get('screenshotThumbnailId'))
            else:
                thumbnail = {'thumbnail': ""}
            iocs = dsapi.get_intel_incident_iocs(data.get('id')).json()
            yield build_alert(data, iocs, thumbnail)
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
        response = thapi.create_alert(a)

def run():
    """
        Download DigitalShadows incident and create a new Case in TheHive
        :argv (options, log, since, intel, incident)
    """

    parser = argparse.ArgumentParser(description="Get DS alerts and create alerts in TheHive")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
                        help="generate a log file and and active debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")
    parser_incident = subparsers.add_parser('inc', help="specify IDs of incidents to fetch")
    parser_incident.add_argument("-i", "--incidents", metavar="ID", action='store', type=int, nargs='+', help="Get DS incidents by ID")
    parser_incident.add_argument("-I", "--intel-incidents", metavar="ID", action='store', type=int, nargs='+', help="Get DS intel-incidents by ID")
    parser_find = subparsers.add_parser('find', help="find incidents and intel-incidents in time")
    parser_find.add_argument("-s", "--since", metavar="M", nargs=1, type=int,required=True, help="Get all incident since last [M] minutes")
    parser_find.add_argument("-m", "--monitor", action='store_true', default=False,
                        help="active monitoring")
    parser_find.add_argument("-i", action='store_true', default=False,
                        help="Get Digital Shadows incidents only")
    parser_find.add_argument("-I", action='store_true', default=False,
                        help="Get Digital Shadows intel-incidents only")

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    args = parser.parse_args()

    debug = True if 'debug' in args and args.debug else False

    dsapi = DigitalShadowsApi(DigitalShadows)

    if debug:
        logging.basicConfig(filename='{}/ds2th.log'.format(os.path.dirname(os.path.realpath(__file__))),
                                level='DEBUG', format='%(asctime)s %(levelname)s %(message)s')

    if 'intel_incidents' in args and args.intel_incidents is not None:
        intel_incidents = get_intel_incidents(dsapi, args.intel_incidents)
        create_thehive_alerts(TheHive, intel_incidents)

    if 'incidents' in args and args.incidents is not None:
        incidents = get_incidents(dsapi, args.incidents)
        create_thehive_alerts(TheHive, incidents)

    if 'since' in args and args.since is not None:
        since = args.since.pop()
        
        if args.monitor:
            mon = monitoring("{}/ds2th.status".format(os.path.dirname(os.path.realpath(__file__))), int(since))
            mon.start()
            
        if (not args.i ^ args.I) or args.I:
            intel = find_intel_incidents(dsapi, since)
            create_thehive_alerts(TheHive, intel)
        if (not args.i ^ args.I) or args.i:
            incidents = find_incidents(dsapi, since)
            create_thehive_alerts(TheHive, incidents)

        mon.finish() if args.monitor else None
        
if __name__ == '__main__':
    run()
