import json
import os
import unittest
import requests

from nightfall.api import Nightfall
from unittest.mock import MagicMock

class TestNightfallIntegration(unittest.TestCase):

    def setUp(self):
        self.client = Nightfall(
            os.getenv('NIGHTFALL_TOKEN'),
            os.getenv('NIGHTFALL_CONDITION_SET')
            )

    def test_scan(self):
        """Test basics of API, can submit a request and receive a response.
        
        This test assumes that you don't have a condition set matching the 'testing' string.
        """
        resp = self.client.scan({"id1": "testing"})

        self.assertEqual(resp['id1'], None)
