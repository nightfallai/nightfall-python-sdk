"""
nightfall.api
~~~~~~~~~~~~~

    This module provides a class which abstracts the Nightfall REST API.
"""
import json
import requests
import logging

from nightfall.exceptions import InputError


class Nightfall():
    """A python interface for the Nightfall API.

    .. data:: MAX_PAYLOAD_SIZE

        Maximum payload size in bytes that the Nightfall API will accept

    .. data:: MAX_NUM_ITEMS

        Maximum number of items that the Nightfall API will accept
    """
    MAX_PAYLOAD_SIZE = 500_000
    MAX_NUM_ITEMS = 50_000

    def __init__(self, token, condition_set):
        """Instantiate a new Nightfall object.

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
        self.logger = logging.getLogger(__name__)

    def make_payloads(self, data):
        """Turn a list of dicts ``[{'id': 'string'},]`` into a list of
        acceptable payloads.

        Creates chunks based on the ``MAX_PAYLOAD_SIZE`` and ``MAX_NUM_ITEMS``
        constants.

        When the number of items in a list is greater than ``MAX_NUM_ITEMS``
        we will split the list into multiple lists. When the total sum of all
        strings in a list is greater than ``MAX_PAYLOAD_SIZE``, we will split
        that list into multiple lists.

        :param data: list of dicts
        :type data: list

        :raises InputError: when individual dictionary item is larger than
            ``MAX_PAYLOAD_SIZE``

        :returns: list of list of dicts to scan
        """
        cur_chunk_bytes = 0
        cur_chunk = []
        chunks = []

        for item in data:
            for k, v in item.items():
                if cur_chunk_bytes + len(v) >= self.MAX_PAYLOAD_SIZE or \
                        len(cur_chunk) >= self.MAX_NUM_ITEMS:
                    if cur_chunk:
                        chunks.append(cur_chunk)
                        cur_chunk = []
                    cur_chunk_bytes = len(v)
                    if len(v) <= self.MAX_PAYLOAD_SIZE:
                        cur_chunk = [item]
                    else:
                        err_msg = f"Unable to scan string with id: '{k}'; " \
                                  f"larger than {self.MAX_PAYLOAD_SIZE} bytes."
                        raise InputError(k, err_msg)
                else:
                    cur_chunk.append(item)
                    cur_chunk_bytes += len(v)
        if cur_chunk:
            chunks.append(cur_chunk)

        return chunks

    def scan(self, data):
        """Scan lists of data with Nightfall.

        This method will convert the list of dicts into chunks if necessary
        and then makes one or more requests to the Nightfall API to scan the
        data.

        data dicts should be in the following format:

        ::

            {
                "id123": "string_to_scan"
            }

        Where the key is a reference to where the string came from, and the
        value is the string that you wish to scan. The keys is not scanned
        and is not considered sensitive.

        response dicts are in the form of:

        ::

            {
                "id123": [{nightfall_findings},] or None
            }
            
        :param data: list of dicts to scan.
        :type data: list
        :returns: list of list of dicts for items in payload.
        """
        responses = []
        chunks = self.make_payloads(data)

        for chunk in chunks:

            payload = []
            for item in chunk:
                payload.append([v for k, v in item.items()][0])

            data = {
                'payload': payload,
                'config': {
                    'conditionSetUUID': self.condition_set
                }
            }

            response = requests.post(
                url=self._url,
                headers=self._headers,
                data=json.dumps(data)
            )

            # Logs for Debugging
            self.logger.debug(f"HTTP Request URL: {response.request.url}")
            self.logger.debug(f"HTTP Request Body: {response.request.body}")
            self.logger.debug(
                f"HTTP Request Headers: {response.request.headers}")

            self.logger.debug(f"HTTP Status Code: {response.status_code}")
            self.logger.debug(f"HTTP Response Headers: {response.headers}")
            self.logger.debug(f"HTTP Response Text: {response.text}")

            response.raise_for_status()
            findings = response.json()

            for idx, d in enumerate(chunk):
                for k, v in d.items():
                    if findings[idx] is not None:
                        responses.append({
                            k: findings[idx]
                        })
                    else:
                        responses.append({k: None})

        return responses
