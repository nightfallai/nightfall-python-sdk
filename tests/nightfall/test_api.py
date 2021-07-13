import json
import os
import unittest
import requests

from nightfall.api import Nightfall
from nightfall.exceptions import InputError
from unittest.mock import MagicMock

class TestNightfallApi(unittest.TestCase):

    def setUp(self):
        self.client = Nightfall(
            'mock_token',
            'mock_condition_set'
            )

    def loadMock(self, filename):
        """helper function to open mock responses"""
        filename = f"tests/mocks/{filename}"

        with open(filename, 'r') as f:
            self.client.scan = MagicMock(return_value=f.read())

    def test_scan(self):
        """basic test of scan function, uses mock response."""
        self.loadMock('mock_single_finding_response')

        resp = json.loads(self.client.scan(["th1Sisaf4k34p1k3y"]))

        self.assertEqual(resp["fragment"], "th1Sisaf4k34p1k3y")


    def test_chunking_big_item_list(self):
        """
        a list of 10 dicts that are 500KB each should turn into a 
        list of 10 lists with one item per list
        """
        large_list = []

        for i in range(0,10):
            large_list.append({
                f"id{i}": "x" * 500000
            })
        
        chunks = self.client.make_payloads(large_list)

        for c in chunks:
            self.assertTrue(len(c) <= self.client.MAX_NUM_ITEMS)
            self.assertEqual(len(c), 1)
            for i in c:
                for k,v in i.items():
                    self.assertTrue(len(v) <= self.client.MAX_PAYLOAD_SIZE)

        self.assertEqual(len(chunks), 10)

    def test_chunking_many_items_list(self):
        """
        a list of 100,000 single byte items should turn into two lists with 
        50,000 items in each list.
        """
        many_list = []
        for i in range(0, 100000):
            many_list.append({
                f"id{i}": "x"
            })

        chunks = self.client.make_payloads(many_list)

        for c in chunks:
            self.assertTrue(len(c) <= self.client.MAX_NUM_ITEMS)
            self.assertEqual(len(c), 50000)
            for i in c:
                for k,v in i.items():
                    self.assertTrue(len(v) <= self.client.MAX_PAYLOAD_SIZE)

        self.assertEqual(len(chunks), 2)

    def test_chunking_huge_item_list(self):
        """A a single 600kb string should raise an exception"""
        large_item_list = []
        large_item_list.append({
            "id": "x" * 600000
        })

        with self.assertRaises(InputError):
            self.client.make_payloads(large_item_list)
