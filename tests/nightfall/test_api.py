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
    
    def testScan(self):
        """Test basics of API, can submit a request and receive a response.
        
        This test assumes that you don't have a condition set matching the 'testing' string.
        """
        resp = self.client.scan(['testing'])
        self.assertEqual(resp[0], None)

    def testChunking(self):
        """Test chunking algorithm."""

        # a list of 10 strings that are 100k bytes each should turn into a 
        # list of three lists
        large_list = []
        large_string = "x" * 100000

        for i in range(0,10):
            large_list.append(large_string)
        
        chunks = self.client.make_payloads(large_list)
        self.assertEqual(len(chunks), 3)

        # a list of 100,000 single byte items should turn into two lists
        many_list = []
        for i in range(0, 100000):
            many_list.append('x')

        chunks = self.client.make_payloads(many_list)
        self.assertEqual(len(chunks), 2)
