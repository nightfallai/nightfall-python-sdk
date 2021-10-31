import os
import pytest

from nightfall.api import Nightfall
from nightfall.detection_rules import DetectionRule, Detector


@pytest.fixture
def nightfall():
    yield Nightfall(os.environ['NIGHTFALL_API_KEY'])


def test_scan_text_detection_rules_v3(nightfall):
    result, _ = nightfall.scan_text(
        ["4916-6734-7572-5015 is my credit card number"],
        detection_rules=[DetectionRule([Detector(min_confidence="LIKELY", min_num_findings=1,
                                                 display_name="Credit Card Number",
                                                 nightfall_detector="CREDIT_CARD_NUMBER")])]
    )

    assert len(result) == 1


def test_scan_file_detection_rules(nightfall):
    file = "file.txt"

    with open(file, "w") as fp:
        fp.write("4916-6734-7572-5015 is my credit card number")

    result = nightfall.scan_file(
        file,
        os.environ['WEBHOOK_ENDPOINT'],
        detection_rules=[DetectionRule([Detector(min_confidence="LIKELY", min_num_findings=1,
                                                 display_name="Credit Card Number",
                                                 nightfall_detector="CREDIT_CARD_NUMBER")])]
    )

    assert all(key in result for key in ['id', 'message'])
    assert result['message'] == 'scan initiated'
