import os

from nightfall.api import Nightfall


def test_scanText_detectionRules():
    nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

    result = nightfall.scanText({
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