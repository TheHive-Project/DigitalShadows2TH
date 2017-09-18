#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import requests
import json

class DigitalShadowsApi():

    def __init__(self, config):
        """
        Python API for DigitalShadows
        :param config
        """

        self.url = config['url']
        self.key = config['ds_key']
        self.secret = config['ds_secret']
        self.proxies = config['proxies']
        self.verify = config['verify']
        self.headers = {
            'Content-Type': 'application/vnd.polaris-v29+json',
            'Accept': 'application/vnd.polaris-v29+json'
        }
        self.session = requests.Session()
        self.auth = requests.auth.HTTPBasicAuth(username=self.key,
                                                password=self.secret)

    def get_incident(self, id, fulltext='true'):
        """
        Fetch DigitalShadows incident
        :param id: int
        :param fulltext: boolean
        :return: requests response object
        """
        req = self.url + '/api/incidents/{}'.format(id)
        headers = self.headers
        try:
            return requests.get(req, headers=headers, auth=self.auth,
                                    proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def get_intel_incident(self, id, fulltext='true'):
        """
        Fetch DigitalShadows Intel Incident
        :param id: int
        :param fulltext: boolean
        :return: requests response
        """
        req = self.url + '/api/intel-incidents/{}?fulltext='.format(id) + fulltext
        headers = self.headers
        try:
            return requests.get(req, headers=headers, auth=self.auth,
                                    proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))


    def find_incidents(self, since, property='published', direction='ASCENDING'):
        """
        Fetch DigitalShadows `published` (default property param) incidents since last `since` minutes
        :param since: int
        :param property: str
        :param direction: str
        :return: requests response
        """
        req = self.url + '/api/incidents/find'
        headers = self.headers
        payload = json.dumps({
          "filter": {
            "severities": [],
            "tags": [],
            "tagOperator": "AND",
            "dateRange": since,
            "dateRangeField": property,
            "types": [],
            "withFeedback": True,
            "withoutFeedback": True,
            "alerted": False,
            "withTakedown": True,
            "withoutTakedown": True,
            "withContentRemoved": True,
            "withoutContentRemoved": True,
            "statuses": [
              "UNREAD",
              "READ"
            ],
            "repostedCredentials": []
          },
          "sort": {
            "property": "date",
            "direction": direction
          },
          "pagination": {
            "size": 50,
            "offset": 0
          },
          "subscribed": True
        })
        try:
            return requests.post(req, headers=headers, auth=self.auth, proxies=self.proxies, data=payload, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def find_intel_incidents(self, since, property='verified', direction='ASCENDING'):
        """
        Fetch DigitalShadows `published` (default property param) intel-incidents since last `since` minutes
        :param since: int
        :param property: str
        :param direction: str
        :return: requests response
        """
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
            return requests.post(req, headers=headers, auth=self.auth, proxies=self.proxies, data=payload, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))


    def get_intel_incident_iocs(self, id):
        """
        Fetch DigitalShadows IOCS for intel-incidents id
        :param id: int
        :return: requests response
        """
        req = "{}/api/intel-incidents/{}/iocs".format(self.url, id)
        headers = self.headers
        payload = json.dumps({
            "filter": {},
            "sort": {
                "property": "value",
                "direction": "ASCENDING"
            }
        })
        try:
            return requests.post(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                     data=payload, verify=self.verify)
        except requests.exceptions.RequestException as e:
                sys.exit("Error: {}".format(e))


    def get_screenshot(self, id):
        """
        Fetch screenshot for incident or intel-incident id
        :param id: int
        :return: requests response
        """
        req = "{}/api/external/downloads/{}".format(self.url, id)
        headers = self.headers
        try:
            return requests.get(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                 verify=self.verify)
        except requests.exceptions.RequestException as e:
                sys.exit("Error: {}".format(e))

    def get_thumbnail(self, id):
        """
        Fetch thumbnail for incident or intel-incident id
        :param id: int
        :return: requests response
        """
        req = "{}/api/thumbnails/{}".format(self.url, id)
        headers = self.headers
        try:
            return requests.get(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                 verify=self.verify)
        except requests.exceptions.RequestException as e:
                sys.exit("Error: {}".format(e))
