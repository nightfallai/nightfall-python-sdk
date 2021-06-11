"""
nightfall.api
~~~~~~~~~~~~~

    This module provides a class which abstracts the Nightfall REST API.
"""
import os
import sys
import json
import requests
import logging

class Api():
    """A python interface into the Nightfall API"""

    def __init__(self, token, condition_set):
        """Instantiate a new nightfall.Api object.

        :param token: Your Nightfall API token.
        :param condition_set: Your Nightfall Condition Set UUID
        """
        self.token = token
        self.condition_set = condition_set
        self._url = 'https://api.nightfall.ai/v2/scan'
        self._headers = {
            'Content-Type': 'application/json',
            'x-api-key': self.token
        }

    def scan(self, data):
        """Scan a piece of data with Nightfall.

        :param data: Data to scan.
        :type data: list
        """
        payload = {
            'payload': data,
            'config': {
                'conditionSetUUID': self.condition_set
            }
        }

        response = requests.post(
            url=self._url,
            headers=self._headers,
            data=json.dumps(payload)
        )
        response.raise_for_status()
        
        return response


