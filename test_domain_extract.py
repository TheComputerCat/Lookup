import unittest
import shodan_data_extract
import os
import json

from common import (
    asHexString,
)

from unittest.mock import (
    patch,
    call,
    Mock,
)

from common import (
    createFixture,
    writeStringToFile,
    setUpWithATextFile,
    tearDownWithATextFile,
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestGetJson(unittest.TestCase):
    pathFile = './data/domain_raw_data/file1'
    @withATextFile(pathToTextFile=pathFile, content='{"someKey": "someValue"}')
    @patch('shodan_data_extract.open', new_callable=Mock, wraps=open)
    def test_getJsonFromFile_withAExistingFile(self, spyOpen, content):
        """
            Read json from file path
        """
        jsonResponse = shodan_data_extract.getJsonFromFile(self.pathFile)

        spyOpen.assert_called_once_with(self.pathFile, 'r')
        self.assertDictEqual(jsonResponse, json.loads(content))
    
    def test_getJsonFromFile_withAExistingFile(self):
        """
            Read json from nonexisting path
        """
        jsonResponse = shodan_data_extract.getJsonFromFile(self.pathFile)
        self.assertDictEqual(jsonResponse, {})

class TestGetData(unittest.TestCase):
    jsonDic = {
        'domain': 'domain.org',
        'tags': [
            'dmarc',
            'spf'
        ],
        'subdomains': [
            'sub1',
            'sub2'
        ],
        'data': [
            {
                'tags': [],
                'subdomain': '',
                'type': 'A',
                'ports': [
                    2222
                ],
                'value': '192.168.1.1',
                'last_seen': '1991-05-17T07:53:21.000000'
            },
            {
                'subdomain': '',
                'type': 'A',
                'value': '172.132.16.77',
                'last_seen': '2011-05-17T01:26:37.000000'
            },
            {
                'subdomain': '',
                'type': 'MX',
                'value': 'mail.domain.org',
                'last_seen': '1991-05-23T15:17:24.000000'
            },
            {
                'subdomain': '',
                'type': 'MX',
                'value': 'mail2.domain.org',
                'last_seen': '1992-05-23T15:17:24.000000'
            },
            {
                "subdomain": "",
                "type": "TXT",
                "value": "v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all",
                "last_seen": "2023-05-23T15:11:10.584000"
            },
            {
                'subdomain': 'sub1',
                'type': 'A',
                "ports": [
                    21,
                    25,
                ],
                'value': 'sub1.domain.org',
                'last_seen': '1996-05-23T15:17:24.000000'
            },
            {
                'subdomain': 'sub2',
                'type': 'MX',
                'value': 'sub2.domain.org',
                'last_seen': '1996-05-23T15:17:24.000000'
            },
            {
                'subdomain': '_dmarc',
                'type': 'TXT',
                'value': 'v=DMARC1; p=none"',
                'last_seen': '1996-05-23T15:17:24.000000',
            }
        ],
        'more': False,
    }
    jsonDataDic = {
        'domain': 'domain.org',
        'main' :{
            'A':[
                {
                    'ports': [
                        2222
                    ],
                    'value': '192.168.1.1',
                    'last_seen': '1991-05-17T07:53:21.000000',
                    
                },
                {
                    'ports': [],
                    'value': '172.132.16.77',
                    'last_seen': '2011-05-17T01:26:37.000000',
                }
            ],
            'MX': [
                {
                    'value': 'mail.domain.org',
                    'last_seen': '1991-05-23T15:17:24.000000'
                },
                {
                    'value': 'mail2.domain.org',
                    'last_seen': '1992-05-23T15:17:24.000000'
                }
            ],
            'TXT':[
                {
                    "value": "v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all",
                    "last_seen": "2023-05-23T15:11:10.584000"
                }
            ]
        },
        'subdomains': {
            'A':[
                {   
                    'subdomain': 'sub1',
                    'ports': [
                        21,
                        25,
                    ],
                    'value': 'sub1.domain.org',
                    'last_seen': '1996-05-23T15:17:24.000000',
                }
            ],
            'MX': [
                {
                    'subdomain': 'sub2',
                    'value': 'sub2.domain.org',
                    'last_seen': '1996-05-23T15:17:24.000000',
                }
            ],
            'TXT': [
                {
                    'subdomain': '_dmarc',
                    'value': 'v=DMARC1; p=none"',
                    'last_seen': '1996-05-23T15:17:24.000000',
                }
            ]
        }
    }
    def test_filterDataFomJson_withAExistingFile(self):
        """
            Get Data from a empty json dictionary
        """
        jsonResponse = shodan_data_extract.filterJson(self.jsonDic)

        self.maxDiff = None

        self.assertDictEqual(jsonResponse, self.jsonDataDic)
if __name__ == '__main__':
     unittest.main()