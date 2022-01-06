
"""
nightfall.api
~~~~~~~~~~~~~
    This module provides a class which abstracts the Nightfall REST API.
"""
from datetime import datetime, timedelta
import hmac
import hashlib
import logging
import os
from typing import List, Tuple, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from nightfall.detection_rules import DetectionRule, RedactionConfig
from nightfall.exceptions import NightfallUserError, NightfallSystemError
from nightfall.findings import Finding


class Nightfall:
    PLATFORM_URL = "https://api.nightfall.ai"
    TEXT_SCAN_ENDPOINT_V3 = PLATFORM_URL + "/v3/scan"
    FILE_SCAN_INITIALIZE_ENDPOINT = PLATFORM_URL + "/v3/upload"
    FILE_SCAN_UPLOAD_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}"
    FILE_SCAN_COMPLETE_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}/finish"
    FILE_SCAN_SCAN_ENDPOINT = PLATFORM_URL + "/v3/upload/{0}/scan"

    def __init__(self, key: Optional[str] = None, signing_secret: Optional[str] = None):
        """Instantiate a new Nightfall object.
        :param key: Your Nightfall API key. If None it will be read from the environment variable NIGHTFALL_API_KEY.
        :type key: str or None
        :param signing_secret: Your Nightfall signing secret used for webhook validation.
        :type signing_secret: str or None
        """
        if key:
            self.key = key
        else:
            self.key = os.getenv("NIGHTFALL_API_KEY")

        if not self.key:
            raise NightfallUserError("need an API key either in constructor or in NIGHTFALL_API_KEY environment var",
                                     40001)

        self.signing_secret = signing_secret
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        retries = Retry(total=5, allowed_methods=Retry.DEFAULT_ALLOWED_METHODS | {"PATCH", "POST"})
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        self.session.headers = {
            "Content-Type": "application/json",
            "User-Agent": "nightfall-python-sdk/1.3.0",
            'Authorization': f'Bearer {self.key}',
        }

    def scan_text(self, texts: List[str], detection_rules: Optional[List[DetectionRule]] = None,
                  detection_rule_uuids: Optional[List[str]] = None, context_bytes: Optional[int] = None,
                  default_redaction_config: Optional[RedactionConfig] = None) ->\
            Tuple[List[List[Finding]], List[str]]:
        """Scan text with Nightfall.

        This method takes the specified config and then makes
        one or more requests to the Nightfall API for scanning.
        At least one of detection_rule_uuids or detection_rules is required.


        :param texts: List of strings to scan.
        :type texts: List[str]
        :param detection_rules: List of detection rules to scan each text with.
        :type detection_rules: List[DetectionRule] or None
        :param detection_rule_uuids: List of detection rule UUIDs to scan each text with.
            These can be created in the Nightfall UI.
        :type detection_rule_uuids: List[str] or None
        :param context_bytes: The number of bytes of context (leading and trailing) to return with any matched findings.
        :type context_bytes: int or None
        :param default_redaction_config: The default redaction configuration to apply to all detection rules, unless
            there is a more specific config within a detector.
        :type default_redaction_config: RedactionConfig or None
        :returns: list of findings, list of redacted input texts
        """

        if not detection_rule_uuids and not detection_rules:
            raise NightfallUserError("at least one of detection_rule_uuids or detection_rules required", 40001)

        config = {}
        if detection_rule_uuids:
            config["detectionRuleUUIDs"] = detection_rule_uuids
        if detection_rules:
            config["detectionRules"] = [d.as_dict() for d in detection_rules]
        if context_bytes:
            config["contextBytes"] = context_bytes
        if default_redaction_config:
            config["defaultRedactionConfig"] = default_redaction_config.as_dict()
        request_body = {
            "payload": texts,
            "config": config
        }
        response = self._scan_text_v3(request_body)

        _validate_response(response, 200)

        parsed_response = response.json()

        findings = [[Finding.from_dict(f) for f in item_findings] for item_findings in parsed_response["findings"]]
        return findings, parsed_response.get("redactedPayload")

    def _scan_text_v3(self, data: dict):
        response = self.session.post(url=self.TEXT_SCAN_ENDPOINT_V3, json=data)

        self.logger.debug(f"HTTP Request URL: {response.request.url}")
        self.logger.debug(f"HTTP Request Body: {response.request.body}")
        self.logger.debug(f"HTTP Request Headers: {response.request.headers}")
        self.logger.debug(f"HTTP Status Code: {response.status_code}")
        self.logger.debug(f"HTTP Response Headers: {response.headers}")
        self.logger.debug(f"HTTP Response Text: {response.text}")

        return response

    # File Scan

    def scan_file(self, location: str, webhook_url: Optional[str] = None, policy_uuid: Optional[str] = None,
                  detection_rules: Optional[List[DetectionRule]] = None,
                  detection_rule_uuids: Optional[List[str]] = None,
                  request_metadata: Optional[str] = None) -> Tuple[str, str]:
        """Scan file with Nightfall.
        At least one of policy_uuid, detection_rule_uuids or detection_rules is required.

        :param location: location of file to scan.
        :param webhook_url: webhook endpoint which will receive the results of the scan.
        :param policy_uuid: policy UUID.
        :type policy_uuid: str or None
        :param detection_rules: list of detection rules.
        :type detection_rules: List[DetectionRule] or None
        :param detection_rule_uuids: list of detection rule UUIDs.
        :type detection_rule_uuids: List[str] or None
        :param request_metadata: additional metadata that will be returned with the webhook response
        :type request_metadata: str or None
        :returns: (scan_id, message)
        """

        if not policy_uuid and not detection_rule_uuids and not detection_rules:
            raise NightfallUserError("at least one of policy_uuid, detection_rule_uuids or detection_rules required",
                                     40001)

        response = self._file_scan_initialize(location)
        _validate_response(response, 200)
        result = response.json()
        session_id, chunk_size = result['id'], result['chunkSize']

        uploaded = self._file_scan_upload(session_id, location, chunk_size)
        if not uploaded:
            raise NightfallSystemError("File upload failed", 50000)

        response = self._file_scan_finalize(session_id)
        _validate_response(response, 200)

        response = self._file_scan_scan(session_id,
                                        detection_rules=detection_rules,
                                        detection_rule_uuids=detection_rule_uuids,
                                        webhook_url=webhook_url, policy_uuid=policy_uuid,
                                        request_metadata=request_metadata)
        _validate_response(response, 200)
        parsed_response = response.json()

        return parsed_response["id"], parsed_response["message"]

    def _file_scan_initialize(self, location: str):
        data = {
            "fileSizeBytes": os.path.getsize(location)
        }
        response = self.session.post(url=self.FILE_SCAN_INITIALIZE_ENDPOINT, json=data)

        return response

    def _file_scan_upload(self, session_id: str, location: str, chunk_size: int):

        def read_chunks(fp, chunk_size):
            ix = 0
            while True:
                data = fp.read(chunk_size)
                if not data:
                    break
                yield ix, data
                ix = ix + 1

        def upload_chunk(id, data, headers):
            response = self.session.patch(
                url=self.FILE_SCAN_UPLOAD_ENDPOINT.format(id),
                data=data,
                headers=headers
            )
            return response

        with open(location, 'rb') as fp:
            for ix, piece in read_chunks(fp, chunk_size):
                headers = {"X-UPLOAD-OFFSET": str(ix * chunk_size)}
                response = upload_chunk(session_id, piece, headers)
                _validate_response(response, 204)

        return True

    def _file_scan_finalize(self, session_id: str):
        response = self.session.post(url=self.FILE_SCAN_COMPLETE_ENDPOINT.format(session_id))
        return response

    def _file_scan_scan(self, session_id: str, detection_rules: Optional[List[DetectionRule]] = None,
                        detection_rule_uuids: Optional[List[str]] = None, webhook_url: Optional[str] = None,
                        policy_uuid: Optional[str] = None, request_metadata: Optional[str] = None) -> requests.Response:
        if policy_uuid:
            data = {"policyUUID": policy_uuid}
        else:
            data = {"policy": {"webhookURL": webhook_url}}
            if detection_rule_uuids:
                data["policy"]["detectionRuleUUIDs"] = detection_rule_uuids
            if detection_rules:
                data["policy"]["detectionRules"] = [d.as_dict() for d in detection_rules]

        if request_metadata:
            data["requestMetadata"] = request_metadata

        response = self.session.post(url=self.FILE_SCAN_SCAN_ENDPOINT.format(session_id), json=data)
        return response

    def validate_webhook(self, request_signature: str, request_timestamp: str, request_data: str) -> bool:
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
        request_datetime = datetime.fromtimestamp(int(request_timestamp))
        if request_datetime < now-timedelta(minutes=5) or request_datetime > now:
            return False
        computed_signature = hmac.new(
            self.signing_secret.encode(),
            msg=F"{request_timestamp}:{request_data}".encode(),
            digestmod=hashlib.sha256
        ).hexdigest().lower()
        if computed_signature != request_signature:
            return False
        return True


# Utility
def _validate_response(response: requests.Response, expected_status_code: int):
    if response.status_code == expected_status_code:
        return
    response_json = response.json()
    error_code = response_json.get('code', None)
    if error_code is None:
        raise NightfallSystemError(response.text, 50000)
    if error_code < 40000 or error_code >= 50000:
        raise NightfallSystemError(response.text, error_code)
    else:
        raise NightfallUserError(response.text, error_code)
