
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

    def scan_text(self, text: str, detection_rule_uuids: list = None, detection_rules: list = None):
        """Scan text with Nightfall.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.

        Either detection_rule_uuids or detection_rules is required.
        ::
            detection_rule_uuids: ["uuid",]
            detection_rules: [{detection_rule},]

        :param text: text to scan.
        :type text: str
        :param detection_rule_uuids: list of detection rule UUIDs.
        :type detection_rule_uuids: list
        :param detection_rules: list of detection rules.
        :type detection_rules: list
        :returns: array with findings.
        """

        if not detection_rule_uuids and not detection_rules:
            raise Exception("Need to supply detection rule ids list or detection rules dict with \
                key 'detection_rule_uuids' or 'detection_rules' respectively")

        if detection_rule_uuids:
            return self._handle_detection_rule_uuids_v3(text, detection_rule_uuids)
        if detection_rules:
            return self._handle_detection_rules_v3(text, detection_rules)

    def _handle_detection_rule_uuids_v3(self, text, detection_rule_uuids):
        text_chunked = self._chunk_text(text)
        all_responses = []
        for payload in text_chunked:
            request_body = {
                "payload": payload,
                "config": {
                    "detectionRuleUUIDs": detection_rule_uuids
                }
            }
            response = self._scan_text_v3(request_body)
            all_responses.extend(response.json()['findings'])
        return all_responses

    def _handle_detection_rules_v3(self, text, detection_rules):
        text_chunked = self._chunk_text(text)
        all_responses = []
        for payload in text_chunked:
            request_body = {
                "payload": payload,
                "config": {
                    "detectionRules": detection_rules
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

    def scan_text_v2(self, text: str, detection_rule_uuids: list = None, detection_rules: list = None):
        """Scan text with Nightfall via the v2 endpoint.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.

        Either detection_rule_uuids or detection_rules is required.
        ::
            detection_rule_uuids: ["uuid",]
            detection_rules: [{detection_rule},]

        If `detection_rule_uuids` is provided, each element in the response list
        correponds to a single detection rule being applied to each string in the text list.

        If `detection_rules` is provided, each element in the response list
        corresponds to a single string being scanned by every detection rule.

        :param text: text to scan.
        :type text: str
        :param detection_rule_uuids: list of detection rule UUIDs.
        :type detection_rule_uuids: list
        :param detection_rules: list of detection rules.
        :type detection_rules: list
        :returns: array with findings.
        """

        if not detection_rule_uuids and not detection_rules:
            raise Exception("Need to supply detection rule ids list or detection rules dict with \
                key 'detection_rule_uuids' or 'detection_rules' respectively")

        if detection_rule_uuids:
            return self._handle_detection_rule_uuids_v2(text, detection_rule_uuids)
        if detection_rules:
            return self._handle_detection_rules_v2(text, detection_rules)

    def _handle_detection_rule_uuids_v2(self, text, detection_rule_uuids):
        text_chunked = self._chunk_text(text)
        all_responses = []
        for payload in text_chunked:
            for detection_rule_uuid in detection_rule_uuids:
                request_body = {
                    "payload": payload,
                    "config": {
                        "conditionSetUUID": detection_rule_uuid
                    }
                }
                response = self._scan_text_v2(request_body)
                all_responses.append(response.json())
        return all_responses

    def _handle_detection_rules_v2(self, text, detection_rules):
        text_chunked = self._chunk_text(text)
        all_responses = []
        for payload in text_chunked:
            request_body = {
                "payload": payload,
                "config": {
                    "conditionSet": {
                        "conditions": detection_rules
                    }
                }
            }
            response = self._scan_text_v2(request_body)
            all_responses.extend(response.json())
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

    def scan_file(self, location: str, webhook_url: str, policy_uuid: str = None,
                  detection_rule_uuids: list = None, detection_rules: list = None):
        """Scan file with Nightfall.

        Either policy_uuid or detection_rule_uuids or detection_rules is required.
        ::
            policy_uuid: "uuid"
            detection_rule_uuids: ["uuid",]
            detection_rules: [{detection_rule},]

        :param location: location of file to scan.
        :type text: str
        :param webhook_url: webhook endpoint which will receive the results of the scan.
        :type text: str
        :param policy_uuid: policy UUID.
        :type policy_uuid: str
        :param detection_rule_uuids: list of detection rule UUIDs.
        :type detection_rule_uuids: list
        :param detection_rules: list of detection rules.
        :type detection_rules: list
        """

        if not policy_uuid and not detection_rule_uuids and not detection_rules:
            raise Exception("Need to supply policy id or detection rule ids list or detection rules dict with \
                key 'policy_uuid', 'detection_rule_uuids', 'detection_rules' respectively")

        response = self._file_scan_initialize(location)
        if response.status_code != 200:
            raise Exception(json.dumps(response.json()))
        result = response.json()
        id, chunk_size = result['id'], result['chunkSize']

        uploaded = self._file_scan_upload(id, location, chunk_size)
        if not uploaded:
            raise Exception("File upload failed")

        response = self._file_scan_finalize(id)
        if response.status_code != 200:
            raise Exception(json.dumps(response.json()))

        response = self._file_scan_scan(id, webhook_url,
                                        policy_uuid=policy_uuid,
                                        detection_rule_uuids=detection_rule_uuids,
                                        detection_rules=detection_rules)
        if response.status_code != 200:
            raise Exception(json.dumps(response.json()))

        return response.json()

    def _file_scan_initialize(self, location: str):
        data = {
            "fileSizeBytes": os.path.getsize(location)
        }
        response = requests.post(
            url=self.FILE_SCAN_INITIALIZE_ENDPOINT,
            headers=self._headers,
            data=json.dumps(data)
        )

        return response

    def _file_scan_upload(self, id, location: str, chunk_size: int):

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
            for ix, piece in read_chunks(fp, chunk_size):
                headers = self._headers
                headers["X-UPLOAD-OFFSET"] = str(ix * chunk_size)
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

    def _file_scan_scan(self, id, webhook_url, policy_uuid: str, detection_rule_uuids: str, detection_rules: str):
        if policy_uuid:
            data = {
                "policyUUID": policy_uuid
            }
        elif detection_rule_uuids:
            data = {
                "policy": {
                    "webhookURL": webhook_url,
                    "detectionRuleUUIDs": detection_rule_uuids
                }
            }
        else:
            data = {
                "policy": {
                    "webhookURL": webhook_url,
                    "detectionRules": detection_rules
                }
            }

        response = requests.post(
            url=self.FILE_SCAN_SCAN_ENDPOINT.format(id),
            headers=self._headers,
            data=json.dumps(data)
        )
        return response

    def validate_webhook(self, request_signature: str, request_timestamp: str, request_data: str):
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
