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
    """A python interface for the Nightfall API.

    .. data:: MAX_PAYLOAD_SIZE 

        Maximum payload size that the Nightfall API will accept 

    .. data:: MAX_NUM_ITEMS

        Maximum number of items that the Nightfall API will accept
    """
    MAX_PAYLOAD_SIZE = 450_000
    MAX_NUM_ITEMS = 50_000

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

    def make_payloads(self, data):
        """Turn a list of strings into a list of acceptable payloads.

        Creates chunks based on the MAX_PAYLOAD_SIZE and MAX_NUM_ITEMS 
        constants.

        :param data: list of string
        :returns: list of list of strings
        """
        cur_chunk_bytes = 0
        cur_chunk = []
        chunks = []

        for i in data:
            if cur_chunk_bytes + len(i) >= self.MAX_PAYLOAD_SIZE or \
                len(cur_chunk) >= self.MAX_NUM_ITEMS:
                chunks.append(cur_chunk)

                cur_chunk_bytes = len(i)

                if len(i) < self.MAX_PAYLOAD_SIZE:
                    cur_chunk = [i]
                else:
                    cur_chunk = []
                    for i in range(0, len(i), self.MAX_PAYLOAD_SIZE):
                        chunks.append([i[i:i+self.MAX_PAYLOAD_SIZE]])

            else:
                cur_chunk.append(i)
                cur_chunk_bytes += len(i)
        if cur_chunk:
            chunks.append(cur_chunk)

        return chunks


    def scan(self, data):
        """Scan lists of data with Nightfall.

        This method will convert the list of strings into chunks if necessary 
        and then makes one or more requests to the Nightfall API to scan the 
        data.

        :param data: list of strings to scan.
        :type data: list

        :returns: list of list of resposes for items in payload.
        """
        responses = []

        for i in self.make_payloads(data):
            payload = {
                'payload': i,
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
            responses += response.json()
        
        return responses



