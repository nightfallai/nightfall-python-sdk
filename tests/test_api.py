import json
import os

from freezegun import freeze_time
import pytest
import responses
import time

from nightfall.api import Nightfall, NightfallUserError
from nightfall.detection_rules import DetectionRule, Detector, LogicalOp, Confidence, ExclusionRule, ContextRule, \
    WordList, MatchType, RedactionConfig, MaskConfig, Regex
from nightfall.findings import Finding, Range


@pytest.fixture
def nightfall():
    yield Nightfall(os.environ['NIGHTFALL_API_KEY'])


@pytest.mark.integration
def test_scan_text_detection_rules_v3(nightfall):
    result, redactions = nightfall.scan_text(
        ["4916-6734-7572-5015 is my credit card number"],
        detection_rules=[DetectionRule(logical_op=LogicalOp.ANY, detectors=[
            Detector(min_confidence=Confidence.LIKELY,
                     min_num_findings=1,
                     display_name="Credit Card Number",
                     nightfall_detector="CREDIT_CARD_NUMBER",
                     context_rules=[ContextRule(regex=Regex("fake regex", is_case_sensitive=False),
                                                window_before=10, window_after=10,
                                                fixed_confidence=Confidence.VERY_UNLIKELY)],
                     exclusion_rules=[ExclusionRule(MatchType.FULL,
                                                    word_list=WordList(["never", "match"],
                                                                       is_case_sensitive=True))],
                     redaction_config=RedactionConfig(remove_finding=False,
                                                      mask_config=MaskConfig(masking_char='👀',
                                                                             num_chars_to_leave_unmasked=3,
                                                                             chars_to_ignore=["-"])),
                     )])],
        context_bytes=10,
    )

    assert len(result) == 1
    assert result[0][0] == Finding(
        "4916-6734-7572-5015",
        '491👀-👀👀👀👀-👀👀👀👀-👀👀👀👀',
        None, " is my cre",
        "Credit Card Number",
        result[0][0].detector_uuid,
        Confidence.VERY_LIKELY,
        Range(0, 19), Range(0, 19),
        [], ["Inline Detection Rule #1"])
    assert len(redactions) == 1
    assert redactions[0] == "491👀-👀👀👀👀-👀👀👀👀-👀👀👀👀 is my credit card number"


@pytest.mark.filetest
@pytest.mark.integration
def test_scan_file_detection_rules(nightfall, tmpdir):
    file = tmpdir.mkdir("test_data").join("file.txt")

    file.write("4916-6734-7572-5015 is my credit card number")

    id, message = nightfall.scan_file(
        file,
        os.environ['WEBHOOK_ENDPOINT'],
        detection_rules=[DetectionRule(logical_op=LogicalOp.ANY, detectors=[
            Detector(min_confidence=Confidence.LIKELY, min_num_findings=1,
                     display_name="Credit Card Number", nightfall_detector="CREDIT_CARD_NUMBER")])]
    )

    assert id is not None
    assert message == 'scan initiated'


@responses.activate
def test_scan_text():
    nightfall = Nightfall("NF-NOT_REAL")
    responses.add(responses.POST, 'https://api.nightfall.ai/v3/scan',
                  json={
                      "findings":
                          [
                              [
                                  {
                                      "finding": "4916-6734-7572-5015",
                                      "redactedFinding": "491👀-👀👀👀👀-👀👀👀👀-👀👀👀👀",
                                      "afterContext": " is my cre",
                                      "detector":
                                          {
                                              "name": "Credit Card Number",
                                              "uuid": "74c1815e-c0c3-4df5-8b1e-6cf98864a454"
                                          },
                                      "confidence": "VERY_LIKELY",
                                      "location":
                                          {
                                              "byteRange":
                                                  {
                                                      "start": 0,
                                                      "end": 19
                                                  },
                                              "codepointRange":
                                                  {
                                                      "start": 0,
                                                      "end": 19
                                                  }
                                          },
                                      "redactedLocation":
                                          {
                                              "byteRange":
                                                  {
                                                      "start": 0,
                                                      "end": 19
                                                  },
                                              "codepointRange":
                                                  {
                                                      "start": 0,
                                                      "end": 19
                                                  }
                                          },
                                      "matchedDetectionRuleUUIDs":
                                          [],
                                      "matchedDetectionRules":
                                          [
                                              "Inline Detection Rule #1"
                                          ]
                                  }
                              ]
                          ],
                      "redactedPayload":
                          [
                              "491👀-👀👀👀👀-👀👀👀👀-👀👀👀👀 is my credit card number"
                          ]
                  })
    result, redactions = nightfall.scan_text(
        ["4916-6734-7572-5015 is my credit card number"],
        detection_rules=[DetectionRule(logical_op=LogicalOp.ANY, detectors=[
            Detector(min_confidence=Confidence.LIKELY,
                     min_num_findings=1,
                     display_name="Credit Card Number",
                     nightfall_detector="CREDIT_CARD_NUMBER",
                     context_rules=[ContextRule(regex=Regex("fake regex", is_case_sensitive=False),
                                                window_before=10, window_after=10,
                                                fixed_confidence=Confidence.VERY_UNLIKELY)],
                     exclusion_rules=[ExclusionRule(MatchType.FULL,
                                                    word_list=WordList(["never", "match"],
                                                                       is_case_sensitive=True))],
                     redaction_config=RedactionConfig(remove_finding=False,
                                                      mask_config=MaskConfig(masking_char='👀',
                                                                             num_chars_to_leave_unmasked=3,
                                                                             chars_to_ignore=["-"])),
                     )])],
        context_bytes=10,
    )

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers.get("Authorization") == "Bearer NF-NOT_REAL"
    assert json.loads(responses.calls[0].request.body) == {
        "payload":
            [
                "4916-6734-7572-5015 is my credit card number"
            ],
        "config":
            {
                "detectionRules":
                    [
                        {
                            "detectors":
                                [
                                    {
                                        "minConfidence": "LIKELY",
                                        "minNumFindings": 1,
                                        "nightfallDetector": "CREDIT_CARD_NUMBER",
                                        "detectorType": "NIGHTFALL_DETECTOR",
                                        "displayName": "Credit Card Number",
                                        "contextRules":
                                            [
                                                {
                                                    "regex":
                                                        {
                                                            "pattern": "fake regex",
                                                            "isCaseSensitive": False
                                                        },
                                                    "proximity":
                                                        {
                                                            "windowBefore": 10,
                                                            "windowAfter": 10
                                                        },
                                                    "confidenceAdjustment":
                                                        {
                                                            "fixedConfidence": "VERY_UNLIKELY"
                                                        }
                                                }
                                            ],
                                        "exclusionRules":
                                            [
                                                {
                                                    "matchType": "FULL",
                                                    "wordList":
                                                        {
                                                            "values":
                                                                [
                                                                    "never",
                                                                    "match"
                                                                ],
                                                            "isCaseSensitive": True
                                                        },
                                                    "exclusionType": "WORD_LIST"
                                                }
                                            ],
                                        "redactionConfig":
                                            {
                                                "removeFinding": False,
                                                "maskConfig":
                                                    {
                                                        "maskingChar": "👀",
                                                        "numCharsToLeaveUnmasked": 3,
                                                        "maskRightToLeft": False,
                                                        "charsToIgnore":
                                                            [
                                                                "-"
                                                            ]
                                                    }
                                            }
                                    }
                                ],
                            "logicalOp": "ANY"
                        }
                    ],
                "contextBytes": 10
            }
    }

    assert len(result) == 1
    assert result[0][0] == Finding(
        "4916-6734-7572-5015",
        '491👀-👀👀👀👀-👀👀👀👀-👀👀👀👀',
        None, " is my cre",
        "Credit Card Number",
        result[0][0].detector_uuid,
        Confidence.VERY_LIKELY,
        Range(0, 19), Range(0, 19),
        [], ["Inline Detection Rule #1"])
    assert len(redactions) == 1
    assert redactions[0] == "491👀-👀👀👀👀-👀👀👀👀-👀👀👀👀 is my credit card number"


def test_scan_text_no_detection_rules():
    nightfall = Nightfall("NF-NOT_REAL")
    with pytest.raises(NightfallUserError):
        nightfall.scan_text(texts=["will", "fail"])


@responses.activate
def test_scan_file(tmpdir):
    file = tmpdir.mkdir("test_data").join("file.txt")

    file.write("4916-6734-7572-5015 is my credit card number")

    nightfall = Nightfall("NF-NOT_REAL")
    responses.add(responses.POST, 'https://api.nightfall.ai/v3/upload', status=200, json={"id": 1, "chunkSize": 22})
    responses.add(responses.PATCH, 'https://api.nightfall.ai/v3/upload/1', status=204)
    responses.add(responses.POST, 'https://api.nightfall.ai/v3/upload/1/finish', status=200)
    responses.add(responses.POST, 'https://api.nightfall.ai/v3/upload/1/scan', status=200,
                  json={"id": 1, "message": "scan_started"})

    id, message = nightfall.scan_file(file, "https://my-website.example/callback", detection_rule_uuids=["a_uuid"], request_metadata="some test data")

    assert len(responses.calls) == 5
    for call in responses.calls:
        assert call.request.headers.get("Authorization") == "Bearer NF-NOT_REAL"

    assert responses.calls[0].request.body == b'{"fileSizeBytes": 44}'
    assert responses.calls[1].request.body == b"4916-6734-7572-5015 is"
    assert responses.calls[1].request.headers.get("X-UPLOAD-OFFSET") == '0'
    assert responses.calls[2].request.body == b" my credit card number"
    assert responses.calls[2].request.headers.get("X-UPLOAD-OFFSET") == '22'
    assert responses.calls[4].request.body == b'{"policy": {"webhookURL": "https://my-website.example/callback", ' \
                                              b'"detectionRuleUUIDs": ["a_uuid"]}, "requestMetadata": "some test data"}'
    assert id == 1
    assert message == "scan_started"


@responses.activate
def test_file_scan_upload_short(tmpdir):
    file = tmpdir.mkdir("test_data").join("file.txt")

    file.write("4916-6734-7572-5015 is my credit card number")

    nightfall = Nightfall("NF-NOT_REAL")

    responses.add(responses.PATCH, 'https://api.nightfall.ai/v3/upload/1', status=204)

    assert nightfall._file_scan_upload(1, file, 200)
    assert len(responses.calls) == 1


@responses.activate
def test_file_scan_upload_long(tmpdir):
    file = tmpdir.mkdir("test_data").join("file.txt")
    test_str = b"4916-6734-7572-5015 is my credit card number"
    file.write_binary(test_str)

    responses.add(responses.PATCH, 'https://api.nightfall.ai/v3/upload/1', status=204)

    nightfall = Nightfall("NF-NOT_REAL")

    assert nightfall._file_scan_upload(1, file, 1)
    assert len(responses.calls) == 44
    for i, call in enumerate(responses.calls):
        assert call.request.headers.get("Authorization") == "Bearer NF-NOT_REAL"
        assert call.request.body.decode('utf-8') == test_str.decode('utf-8')[i]
        assert call.request.headers.get("X-UPLOAD-OFFSET") == str(i)
        

@freeze_time("2021-10-04T17:30:50Z")
def test_validate_webhook(nightfall):
    nightfall.signing_secret = "super-secret-shhhh"
    timestamp = 1633368645
    body = "hello world foo bar goodnight moon"
    expected = "1bb7619a9504474ffc14086d0423ad15db42606d3ca52afccb4a5b2125d7b703"
    assert nightfall.validate_webhook(expected, timestamp, body)


@freeze_time("2021-10-04T19:30:50Z")
def test_validate_webhook_too_old(nightfall):
    nightfall.signing_secret = "super-secret-shhhh"
    timestamp = 1633368645
    body = "hello world foo bar goodnight moon"
    expected = "1bb7619a9504474ffc14086d0423ad15db42606d3ca52afccb4a5b2125d7b703"
    assert not nightfall.validate_webhook(expected, timestamp, body)


@freeze_time("2021-10-04T17:30:50Z")
def test_validate_webhook_incorrect_sig(nightfall):
    nightfall.signing_secret = "super-secret-shhhh"
    timestamp = 1633368645
    body = "hello world foo bar goodnight moon"
    expected = "not matching"
    assert not nightfall.validate_webhook(expected, timestamp, body)
