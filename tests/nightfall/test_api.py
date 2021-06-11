import json
import os
import unittest
import requests

from nightfall.api import Api

class TestNightfallApi(unittest.TestCase):

    def setUp(self):
        self.client = Api(
            os.getenv('NIGHTFALL_TOKEN'),
            os.getenv('NIGHTFALL_CONDITION_SET')
            )
    
    def testBadScan(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            resp = self.client.scan('')
    
    def testScan(self):
        """Test basics of API, can submit a request and receive a response."""
        resp = self.client.scan(['testing'])
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), None)
        
