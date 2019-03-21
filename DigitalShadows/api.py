#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import requests
import json
import sys

class DigitalShadowsApi():

    def __init__(self, config):
        
        """
        Python API for DigitalShadows
        :param config: Digital Shadows configuration from config.py
        :type config: dict
        """

        self.url = config['url']
        self.key = config['ds_key']
        self.secret = config['ds_secret']
        self.proxies = config['proxies']
        self.verify = config['verify']
        self.headers = {
            'Content-Type': 'application/vnd.polaris-v38+json',
            'Accept': 'application/vnd.polaris-v38+json'
        }
        self.auth = requests.auth.HTTPBasicAuth(username=self.key,
                                                password=self.secret)

    def response(self, status, content):
        
        """
        :param status: str = success/failure
        :type status: string
        :paran content: data to return
        :type content: dict
        :return: 
        :rtype: dict

        """
        
        return {'status':status, 'data': content}

    def get_incident(self, id, fulltext='true'):
        
        """
        Fetch DigitalShadows incident
        :param id: incident id
        :type id: int
        :type fulltext: text
        :return: response 
        :rtype: requests.get
        
        """
        req = self.url + '/api/incidents/{}'.format(id)
        headers = self.headers
        try:
            resp = requests.get(req, headers=headers, auth=self.auth,
                                    proxies=self.proxies, verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def get_intel_incident(self, id, fulltext='true'):
        
        """
        Fetch DigitalShadows Intel Incident
        :param id: intel-incident
        :type id: string
        :type fulltext: boolean
        :return: requests response
        :rtype: requests.get
        """

        req = self.url + '/api/intel-incidents/{}?fulltext='.format(id) + fulltext
        headers = self.headers
        try:
            resp = requests.get(req, headers=headers, auth=self.auth,
                                    proxies=self.proxies, verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))


    def find_incidents(self, since, property='published', direction='ASCENDING'):
        
        """
        Fetch DigitalShadows `published` (default property param) incidents since last `since` minutes
        :type since: int
        :type property: str
        :type direction: str
        :rtype: request.post
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
            resp =  requests.post(req, headers=headers, auth=self.auth, proxies=self.proxies, data=payload, verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def find_intel_incidents(self, since, property='verified', direction='ASCENDING'):
        
        """
        Fetch DigitalShadows `published` (default property param) intel-incidents since last `since` minutes
        :type since: int
        :type property: str
        :type direction: str
        :rtype: requests response
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
            resp = requests.post(req, headers=headers, auth=self.auth, proxies=self.proxies, data=payload, verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))


    def get_intel_incident_iocs(self, id):
        
        """
        Fetch DigitalShadows IOCS for intel-incidents id
        :type id: int
        :rtype: requests response
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
        :type id: int
        :rtype: requests response
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
        :type id: int
        :rtype: requests response
        """

        req = "{}/api/thumbnails/{}".format(self.url, id)
        headers = self.headers
        try:
            return requests.get(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                 verify=self.verify)
        except requests.exceptions.RequestException as e:
                sys.exit("Error: {}".format(e))


    def get_databreach(self, id):
        """
        fetch data leakage information
        :param self:
        :param id: int
        :return: requests response
        """
        req = "{}/api/data-breach/{}".format(self.url, id)
        headers = self.headers
        try:
            return requests.get(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def get_databreach_records(self, id):
        """
        fetch data leakage information
        :param self:
        :param id: int
        :return: requests response
        """
        payload = json.dumps({
          "filter": {
            "published": "ALL",
            "domainNames": [],
            "reviewStatuses": []
          },
          "sort": {
            "property": "username",
            "direction": "ASCENDING"
          },
          "pagination": {
            "size": 1000,
            "offset": 0
          }
        })
        req = "{}/api/data-breach/{}/records".format(self.url, id)
        headers = self.headers
        try:
            resp = requests.post(req, headers=headers, auth=self.auth, proxies=self.proxies,
                                data=payload, verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))