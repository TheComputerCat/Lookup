import dump_domains

import json
import unittest

from common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class testGetRowsFromDomainInfoPage(unittest.TestCase):
    inputJson = json.loads('''{
        "domain": "google.com",
        "tags": [
            "ipv6"
        ],
        "data": [
            {
                "subdomain": "",
                "type": "MX",
                "value": "aspmx.l.google.com",
                "last_seen": "2021-01-19T22:23:15.978799+00:00"
            },
            {
                "subdomain": "*.auth.corp",
                "type": "CNAME",
                "value": "uberproxy.l.google.com",
                "last_seen": "2021-01-26T13:04:34.018114+00:00"
            },
            {
                "subdomain": "*.cloud.sandbox",
                "type": "A",
                "value": "74.125.142.81",
                "last_seen": "2021-01-15T12:57:18.133727+00:00"
            },
            {
                "subdomain": "",
                "type": "A",
                "value": "74.125.142.23",
                "last_seen": "2021-01-15T12:57:18.133727+00:00"
            }
        ],
        "subdomains": [
            "*.auth.corp",
            "*.cloud.sandbox",
            "*.composer-staging.cloud"
        ],
        "more": true
    }''')

    def test_getARegisters(self):
        result = dump_domains.getARegisters(self.inputJson)

        self.assertDictEqual(
            result,
            [
                dump_domains.TypeARegisterRow({
                    "subdomain": "*.cloud.sandbox",
                    "type": "A",
                    "value": "74.125.142.81",
                    "last_seen": "2021-01-15T12:57:18.133727+00:00"
                }),
                dump_domains.TypeARegisterRow({
                "subdomain": "",
                "type": "A",
                "value": "74.125.142.23",
                "last_seen": "2021-01-15T12:57:18.133727+00:00"
                }),
            ]
        )

if __name__ == '__main__':
     unittest.main()

