
"""
nightfall.api
~~~~~~~~~~~~~
    This module provides a class which abstracts the Nightfall REST API.
"""
from datetime import datetime, timedelta
import hmac
import hashlib
import json
import logging
import os
import requests


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
    TEXT_SCAN_ENDPOINT_V2 = PLATFORM_URL + "/v2/scan"
    TEXT_SCAN_ENDPOINT_V3 = PLATFORM_URL + "/v3/scan"
    FILE_SCAN_INITIALIZE_ENDPOINT = PLATFORM_URL + "/v3/upload"
    FILE_SCAN_UPLOAD_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}"
    FILE_SCAN_COMPLETE_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}/finish"
    FILE_SCAN_SCAN_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}/scan"

    def __init__(self, key: str, signing_secret: str = None):
        """Instantiate a new Nightfall object.
        :param key: Your Nightfall API key.
        :param signing_secret: Your Nightfall signing secret used for webhook validation.
        """
        self.key = key
        self._headers = {
            "Content-Type": "application/json",
            "User-Agent": "nightfall-python-sdk/1.0.0",
            "x-api-key": self.key,  # v2
            'Authorization': f'Bearer {self.key}',  # v3
        }
        self.signing_secret = signing_secret
        self.logger = logging.getLogger(__name__)

    # Text Scan V3

    def scanText(self, text, config: dict):
        """Scan text with Nightfall.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.

        config dict should be in the following format:
        ::
            {
                "detectionRuleUuids": ["uuid",],
            }
        or
        ::
            {
                "detectionRules": [{detection_rule},],
            }

        :param text: text to scan.
        :type text: str
        :param config: dict to scan.
        :type config: dict
        :returns: array with findings.
        """

        if "detectionRules" not in config.keys() and "detectionRuleUUIDs" not in config.keys():
            raise Exception("Need to supply detection rule ids list or detection rules dict with \
                key 'detectionRuleUUIDs' or 'detectionRules' respectively")

        if "detectionRules" in config.keys():
            return self._handle_detectionRules_v3(text, config)
        if "detectionRuleUUIDs" in config.keys():
            return self._handle_detectionRuleUuids_v3(text, config)

    def _handle_detectionRules_v3(self, text, config):
        text_chunked = self._chunk_text(text)
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

    def _handle_detectionRuleUuids_v3(self, text, config):
        text_chunked = self._chunk_text(text)
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
            url=self.TEXT_SCAN_ENDPOINT_V3,
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

    def _chunk_text(self, text):
        payload_size = sum([len(string_to_scan) for string_to_scan in text])
        if payload_size <= self.MAX_PAYLOAD_SIZE and len(text) < self.MAX_NUM_ITEMS:
            return [text]
        text_chunked = [[]]
        cur_size = 0
        cur_items = 0
        for t in text:
            if len(t) > self.MAX_PAYLOAD_SIZE:
                raise Exception(f"No individual string can exceed {self.MAX_PAYLOAD_SIZE} bytes")
            if cur_size + len(t) > self.MAX_PAYLOAD_SIZE or cur_items + 1 > self.MAX_NUM_ITEMS:
                text_chunked.append([t])
                cur_size = len(t)
                cur_items = 1
            else:
                text_chunked[-1].append(t)
                cur_size += len(t)
                cur_items += 1
        return text_chunked

    # Text Scan V2

    def scanText_v2(self, text, config: dict):
        """Scan text with Nightfall via the v2 endpoint.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.

        config dict should be in the following format:
        ::
            {
                "detectionRuleUuids": ["uuid",],
            }
        or
        ::
            {
                "detectionRules": [{detection_rule},],
            }

        If `detectionRuleUuids` is provided, each element in the response list
        correponds to a single detection rule being applied to each string in the text list.

        If `detectionRules` is provided, each element in the response list
        corresponds to a single string being scanned by every detection rule.

        :param text: text to scan.
        :type text: str
        :param config: dict to scan.
        :type config: dict
        :returns: array with findings.
        """

        if "detectionRules" not in config.keys() and "detectionRuleUuids" not in config.keys():
            raise Exception("Need to supply detection rule ids list or detection rules dict with \
                key 'detectionRuleUuids' or 'detectionRules' respectively")

        if "detectionRules" in config.keys():
            return self._handle_detectionRules_v2(text, config)
        if "detectionRuleUuids" in config.keys():
            return self._handle_detectionRuleUuids_v2(text, config)

    def _handle_detectionRules_v2(self, text, config):
        text_chunked = self._chunk_text(text)
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

    def _handle_detectionRuleUuids_v2(self, text, config):
        text_chunked = self._chunk_text(text)
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
            url=self.TEXT_SCAN_ENDPOINT_V2,
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

    # File Scan

    def scanFile(self, config: dict):
        if "location" not in config.keys():
            raise Exception("Need to supply file location with key 'location'")
        if "webhookUrl" not in config.keys():
            raise Exception("Need to supply webhook url with key 'webhookUrl'")
        if all(key not in config.keys() for key in ["detectionRules", "detectionRuleUUIDs", "policyUUID"]):
            raise Exception("Need to supply policy id or detection rule ids list or detection rules dict with \
                key 'policyUUID', 'detectionRuleUUIDs', 'detectionRules' respectively")

        location = config["location"]
        webhookUrl = config["webhookUrl"]
        detectionRules = config.get("detectionRules", None)
        detectionRuleUUIDs = config.get("detectionRuleUUIDs", None)
        policyUUID = config.get("policyUUID", None)

        response = self._file_scan_initialize(location)
        if response.status_code != 200:
            raise Exception(json.dumps(response.json()))
        result = response.json()
        id, chunkSize = result['id'], result['chunkSize']

        uploaded = self._file_scan_upload(id, location, chunkSize)
        if not uploaded:
            raise Exception("File upload failed")

        response = self._file_scan_finalize(id)
        if response.status_code != 200:
            raise Exception(json.dumps(response.json()))

        response = self._file_scan_scan(id, webhookUrl,
                                        detectionRules=detectionRules,
                                        detectionRuleUUIDs=detectionRuleUUIDs,
                                        policyUUID=policyUUID)
        if response.status_code != 200:
            raise Exception(json.dumps(response.json()))

        return response.json()

    def _file_scan_initialize(self, location):
        data = {
            "fileSizeBytes": os.path.getsize(location)
        }
        response = requests.post(
            url=self.FILE_SCAN_INITIALIZE_ENDPOINT,
            headers=self._headers,
            data=json.dumps(data)
        )

        return response

    def _file_scan_upload(self, id, location, chunkSize):

        def read_chunks(fp, chunk_size):
            ix = 0
            while True:
                data = fp.read(chunk_size)
                if not data:
                    break
                yield ix, data
                ix = ix + 1

        def upload_chunk(id, data, headers):
            response = requests.patch(
                url=self.FILE_SCAN_UPLOAD_ENDPOINT.format(id),
                data=data,
                headers=headers
            )
            return response

        with open(location) as fp:
            for ix, piece in read_chunks(fp, chunkSize):
                headers = self._headers
                headers["X-UPLOAD-OFFSET"] = str(ix * chunkSize)
                response = upload_chunk(id, piece, headers)
                if response.status_code != 204:
                    raise Exception(json.dumps(response.json))

        return True

    def _file_scan_finalize(self, id):
        response = requests.post(
            url=self.FILE_SCAN_COMPLETE_ENDPOINT.format(id),
            headers=self._headers
        )
        return response

    def _file_scan_scan(self, id, webhookUrl, detectionRules, detectionRuleUUIDs, policyUUID):
        if detectionRules is not None:
            data = {
                "policy": {
                    "webhookURL": webhookUrl,
                    "detectionRules": detectionRules
                }
            }
        elif detectionRuleUUIDs is not None:
            data = {
                "policy": {
                    "webhookURL": webhookUrl,
                    "detectionRuleUUIDs": detectionRuleUUIDs
                }
            }
        else:
            data = {
                "policyUUID": policyUUID
            }

        response = requests.post(
            url=self.FILE_SCAN_SCAN_ENDPOINT.format(id),
            headers=self._headers,
            data=json.dumps(data)
        )
        return response

    def validateWebhook(self, request_signature: str, request_timestamp: str, request_data: str):
        """
        Validate the integrity of webhook requests coming from Nightfall.

        :param request_signature: value of X-Nightfall-Signature header
        :type request_signature: str
        :param request_timestamp: value of X-Nightfall-Timestamp header
        :type request_timestamp: str
        :param request_data: request body as a unicode string
            Flask: request.get_data(as_text=True)
            Django: request.body.decode("utf-8")
        :type request_data: str
        :returns: validation status boolean
        """

        now = datetime.now()
        if now-timedelta(minutes=5) <= datetime.fromtimestamp(int(request_timestamp)) <= now:
            raise Exception("could not validate timestamp is within the last few minutes")
        computed_signature = hmac.new(
            self.signing_secret.encode(),
            msg=F"{request_timestamp}:{request_data}".encode(),
            digestmod=hashlib.sha256
        ).hexdigest().lower()
        if computed_signature != request_signature:
            raise Exception("could not validate signature of inbound request!")
        return True
