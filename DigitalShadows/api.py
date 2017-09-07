#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import requests
import json

class DigitalShadowsApi():
    """
		Python API for DigitalShadows

		:param config
	"""

    def __init__(self, config):

        self.url = config['url']
        self.key = config['ds_key']
        self.secret = config['ds_secret']
        self.proxies = config['proxies']
        self.verify = config['verify']
        self.headers = {
            'Content-Type': 'application/vnd.polaris-v28+json',
            'Accept': 'application/vnd.polaris-v28+json'
        }
        self.session = requests.Session()
        self.auth = requests.auth.HTTPBasicAuth(username=self.key,
                                                password=self.secret)

    def getIncidents(self, id, fulltext='false'):
        req = self.url + '/api/incidents/{}'.format(id)
        headers = self.headers
        try:
            return self.session.get(req, headers=headers, auth=self.auth,
                                    proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def getIntelIncidents(self, id, fulltext='false'):
        req = self.url + '/api/intel-incidents/{}?fulltext='.format(id) + fulltext
        headers = self.headers
        try:
            return self.session.get(req, headers=headers, auth=self.auth,
                                    proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def find_incident(self, since, property='occurred', direction='DESCENDING', detailed='true', fulltext='false'):
        req = self.url + '/api/incidents/find'
        headers = self.headers
        payload = {'since': since , 'sort.property': property, 'sort.direction':direction, 'detailed': detailed, 'fulltext':fulltext}
        try:
            return self.session.get(req, headers=headers, auth=self.auth, proxies=self.proxies, params=payload, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def find_intel_incident(self, since, property='verified', direction='ASCENDING'):
        req = self.url + '/api/intel-incidents/find'
        headers = self.headers

        payload = json.dumps({
              "filter": {
                "severities": [],
                "tags": [],
                "tagOperator": "AND",
                "dateRange": since,
                "dateRangeField": "published",
                "types": [],
                "withFeedback": True,
                "withoutFeedback": True
              },
              "sort": {
                "property": property,
                "direction": direction
              },
              "pagination": {
                "size": 50,
                "offset": 0
              }
            })


        try:
            return self.session.post(req, headers=headers, auth=self.auth, proxies=self.proxies, data=payload, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def get_intel_incident_iocs(self, id):
        req = "{}/api/intel-incidents/{}/iocs".format(self.url, id)
        headers = self.headers
        payload = {
            "filter": {},
            "sort": {
                "property": "value",
                "direction": "ASCENDING"
            }
        }
        try:
            return self.session.post(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                     data=json.dumps(payload), verify=self.verify)
        except requests.exceptions.RequestException as e:
                sys.exit("Error: {}".format(e))


    def get_intel_incident_thumbnail(self, id):
        req = "{}/api/thumbnails/{}".format(self.url, id)
        headers = self.headers
        try:
            return self.session.get(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                 verify=self.verify)
        except requests.exceptions.RequestException as e:
                sys.exit("Error: {}".format(e))
