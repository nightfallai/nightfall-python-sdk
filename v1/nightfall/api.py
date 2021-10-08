
"""
nightfall.api
~~~~~~~~~~~~~
    This module provides a class which abstracts the Nightfall REST API.
"""
import json
import os
import requests
import logging

from requests.api import head


class Nightfall():
    """A python interface for the Nightfall API.
    .. data:: MAX_PAYLOAD_SIZE
        Maximum payload size in bytes that the Nightfall API will accept
    .. data:: MAX_NUM_ITEMS
        Maximum number of items that the Nightfall API will accept
    """
    MAX_PAYLOAD_SIZE = 500_000
    MAX_NUM_ITEMS = 50_000

    PLATFORM_URL = "https://api.nightfall.ai"
    SCAN_V2_ENDPOINT = PLATFORM_URL + "/v2/scan"
    SCAN_V3_ENDPOINT = PLATFORM_URL + "/v3/scan"
    UPLOAD_ENDPOINT = PLATFORM_URL + "/v3/upload"


    def __init__(self, key):
        """Instantiate a new Nightfall object.
        :param key: Your Nightfall API key.
        """
        self.key = key
        self._headers = {
            "Content-Type": "application/json",
            "User-Agent": "nightfall-python-sdk/1.0.0",
            "x-api-key": self.key, # v2
            'Authorization': f'Bearer {self.key}', # v3
        }
        self.logger = logging.getLogger(__name__)

    ### V3 ###

    def scanText(self, config: dict):
        """
        v3 endpoint
        """

        if "text" not in config.keys():
            raise Exception("Need to supply text list with key 'text'")
        if "detectionRules" not in config.keys() and "detectionRuleUUIDs" not in config.keys():
            raise Exception("Need to supply detection rule ids list or detection rules dict with \
                key 'detectionRuleUUIDs' or 'detectionRules' respectively")

        if "detectionRules" in config.keys():
            return self._handle_detectionRules_v3(config)
        if "detectionRuleUUIDs" in config.keys():
            return self._handle_detectionRuleUuids_v3(config)


    def _handle_detectionRules_v3(self, config):
        text_chunked = self._chunk(config["text"])
        detectionRules = config["detectionRules"]
        all_responses = []
        for payload in text_chunked:
            request_body = {
                "payload": payload,
                "config": {
                    "detectionRules": detectionRules
                }
            }
            response = self._scan_text_v3(request_body)
            all_responses.extend(response.json()['findings'])
        return all_responses


    def _handle_detectionRuleUuids_v3(self, config):
        text_chunked = self._chunk(config["text"])
        detectionRuleUuids = config["detectionRuleUUIDs"]
        all_responses = []
        for payload in text_chunked:
            request_body = {
                "payload": payload,
                "config": {
                    "detectionRuleUUIDs": detectionRuleUuids
                }
            }
            response = self._scan_text_v3(request_body)
            all_responses.extend(response.json()['findings'])
        return all_responses


    def _scan_text_v3(self, data):
        response = requests.post(
            url=self.SCAN_V3_ENDPOINT,
            headers=self._headers,
            data=json.dumps(data)
        )

        # Logs for Debugging
        self.logger.debug(f"HTTP Request URL: {response.request.url}")
        self.logger.debug(f"HTTP Request Body: {response.request.body}")
        self.logger.debug(f"HTTP Request Headers: {response.request.headers}")

        self.logger.debug(f"HTTP Status Code: {response.status_code}")
        self.logger.debug(f"HTTP Response Headers: {response.headers}")
        self.logger.debug(f"HTTP Response Text: {response.text}")

        return response

    ### V2 ###

    def scanText_v2(self, config: dict):
        """Scan text with Nightfall.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.

        config dict should be in the following format:
        ::
            {
                "text": ["string_to_scan",],
                "detectionRuleUuids": ["uuid",],
            }
        or
        ::
            {
                "text": ["string_to_scan",],
                "detectionRules": [{detection_rule},],
            }

        If `detectionRuleUuids` is provided, each element in the response list
        correponds to a single detection rule being applied to each string in the text list.

        If `detectionRules` is provided, each element in the response list 
        corresponds to a single string being scanned by every detection rule.
        
        :param config: dict to scan.
        :type config: dict
        :returns: array with findings.
        """

        if "text" not in config.keys():
            raise Exception("Need to supply text list with key 'text'")
        if "detectionRules" not in config.keys() and "detectionRuleUuids" not in config.keys():
            raise Exception("Need to supply detection rule ids list or detection rules dict with \
                key 'detectionRuleUuids' or 'detectionRules' respectively")

        if "detectionRules" in config.keys():
            return self._handle_detectionRules_v2(config)
        if "detectionRuleUuids" in config.keys():
            return self._handle_detectionRuleUuids_v2(config)


    def _handle_detectionRules_v2(self, config):
        text_chunked = self._chunk(config["text"])
        conditions = config["detectionRules"]
        all_responses = []
        for payload in text_chunked:
            request_body = {
                "payload": payload,
                "config": {
                    "conditionSet": {
                        "conditions": conditions
                    }
                }
            }
            response = self._scan_text_v2(request_body)
            all_responses.extend(response.json())
        return all_responses


    def _handle_detectionRuleUuids_v2(self, config):
        text_chunked = self._chunk(config["text"])
        detectionRuleUuids = config["detectionRuleUuids"]
        all_responses = []
        for payload in text_chunked:
            for detectionRuleUuid in detectionRuleUuids:
                request_body = {
                    "payload": payload,
                    "config": {
                        "conditionSetUUID": detectionRuleUuid
                    }
                }
                response = self._scan_text_v2(request_body)
                all_responses.append(response.json())
        return all_responses


    def _scan_text_v2(self, data):
        response = requests.post(
            url=self.SCAN_V2_ENDPOINT,
            headers=self._headers,
            data=json.dumps(data)
        )

        # Logs for Debugging
        self.logger.debug(f"HTTP Request URL: {response.request.url}")
        self.logger.debug(f"HTTP Request Body: {response.request.body}")
        self.logger.debug(f"HTTP Request Headers: {response.request.headers}")

        self.logger.debug(f"HTTP Status Code: {response.status_code}")
        self.logger.debug(f"HTTP Response Headers: {response.headers}")
        self.logger.debug(f"HTTP Response Text: {response.text}")

        return response

    ### Common ###

    def _chunk(self, text):
        payload_size = sum([len(string_to_scan) for string_to_scan in text])
        if payload_size <= self.MAX_PAYLOAD_SIZE:
            return [text]
        text_chunked = [[]]
        cur_size = 0
        for t in text:
            if len(t) > self.MAX_PAYLOAD_SIZE:
                raise Exception(f"No individual string can exceed {self.MAX_PAYLOAD_SIZE} bytes")
            if cur_size + len(t) > self.MAX_PAYLOAD_SIZE:
                text_chunked.append([t])
                cur_size = len(t)
            else:
                cur_size += len(t)
                text_chunked[-1].append(t)
        return text_chunked

