import os
import pytest

from nightfall.api import Nightfall


def test_scanText_detectionRules_v2():
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    result = nightfall.scanText_v2({
        "text": ["4916-6734-7572-5015 is my credit card number"],
        "detectionRules": [
            {
                "minNumFindings": 1,
                "minConfidence": "LIKELY",
                "detector": {
                    "displayName": "Credit Card Number",
                    "detectorType": "NIGHTFALL_DETECTOR",
                    "nightfallDetector": "CREDIT_CARD_NUMBER"
                }
            }
        ]
    })

    assert len(result) == 1


def test_scanText_detectionRules_v3():
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    result = nightfall.scanText({
        "text": ["4916-6734-7572-5015 is my credit card number"],
        "detectionRules": [
            {
                "name": "string",
                "logicalOp": "ANY",
                "minNumFindings": 1,
                "minConfidence": "POSSIBLE",
                "detectors": [
                    {
                        "minNumFindings": 1,
                        "minConfidence": "POSSIBLE",
                        "displayName": "Credit Card Number",
                        "detectorType": "NIGHTFALL_DETECTOR",
                        "nightfallDetector": "CREDIT_CARD_NUMBER"
                    }
                ]
            }
        ]
    })

    assert len(result) == 1


def test_chunking_big_item_list():
    """
    a list of 10 strings that are 500KB each should turn into a
    list of 10 lists with one item per list
    """
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    large_list = ["x" * 500000 for _ in range(10)]

    chunks = nightfall._chunk_text(large_list)

    for c in chunks:
        assert len(c) <= nightfall.MAX_NUM_ITEMS
        assert len(c) == 1
        assert sum([len(string_to_scan) for string_to_scan in c]) <= nightfall.MAX_PAYLOAD_SIZE

    assert len(chunks) == 10


def test_chunking_many_items_list():
    """
    A list of 100,000 single byte items should turn into two lists each
    with 50,000 items.
    """
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    many_list = ["x" for _ in range(100000)]

    chunks = nightfall._chunk_text(many_list)

    for i, c in enumerate(chunks):
        if i == len(chunks) - 1:
            assert len(c) <= nightfall.MAX_NUM_ITEMS
        else:
            assert len(c) == nightfall.MAX_NUM_ITEMS
        assert sum([len(string_to_scan) for string_to_scan in c]) <= nightfall.MAX_PAYLOAD_SIZE

    assert len(chunks) == 2


def test_chunking_huge_item_list():
    """A single 600kb string should raise an exception"""
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    large_item_list = ["x" * 600000]

    with pytest.raises(Exception):
        nightfall._chunk_text(large_item_list)


def test_scanFile_detectionRules():
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    file = "file.txt"

    with open(file, "w") as fp:
        fp.write("4916-6734-7572-5015 is my credit card number")

    result = nightfall.scanFile({
        "location": file,
        "webhookUrl": os.getenv('WEBHOOK_ENDPOINT'),
        "detectionRules": [
            {
                "name": "string",
                "logicalOp": "ANY",
                "minNumFindings": 1,
                "minConfidence": "POSSIBLE",
                "detectors": [
                    {
                        "minNumFindings": 1,
                        "minConfidence": "POSSIBLE",
                        "displayName": "Credit Card Number",
                        "detectorType": "NIGHTFALL_DETECTOR",
                        "nightfallDetector": "CREDIT_CARD_NUMBER"
                    }
                ]
            }
        ]
    })

    assert all(key in result for key in ['id', 'message'])
    assert result['message'] == 'scan initiated'