import host_extract
import json
import unittest

class TestExtractInfoFromRealShodanOutput(unittest.TestCase):
    dictFromJSON = json.loads("""
    {
        "region_code": null,
        "ip": 134744072,
        "postal_code": null,
        "country_code": "US",
        "city": null,
        "dma_code": null,
        "last_update": "2021-01-22T08:49:35.190817",
        "latitude": 37.751,
        "tags": [],
        "area_code": null,
        "country_name": "United States",
        "hostnames": [
            "dns.google"
        ],
        "org": "Google",
        "data": [
            {
                "_shodan": {
                    "id": "cea5795b-55fd-4595-b9e5-ad5ca847cb4b",
                    "options": {},
                    "ptr": true,
                    "module": "dns-udp",
                    "crawler": "ac284849be0745621b3c518f74c14cf43cafbf08"
                },
                "hash": -553166942,
                "os": null,
                "opts": {
                    "raw": "34ef818200010000000000000776657273696f6e0462696e640000100003"
                },
                "ip": 134744072,
                "isp": "Google",
                "port": 53,
                "hostnames": [
                    "dns.google"
                ],
                "location": {
                    "city": null,
                    "region_code": null,
                    "area_code": null,
                    "longitude": -97.822,
                    "country_code3": null,
                    "country_name": "United States",
                    "postal_code": null,
                    "dma_code": null,
                    "country_code": "US",
                    "latitude": 37.751
                },
                "dns": {
                    "resolver_hostname": null,
                    "recursive": true,
                    "resolver_id": null,
                    "software": null
                },
                "timestamp": "2021-01-22T08:49:35.190817",
                "domains": [
                    "dns.google"
                ],
                "org": "Google",
                "data": "Recursion: enabled",
                "asn": "AS15169",
                "transport": "udp",
                "ip_str": "8.8.8.8"
            }
        ],
        "asn": "AS15169",
        "isp": "Google",
        "longitude": -97.822,
        "country_code3": null,
        "domains": [
            "dns.google"
        ],
        "ip_str": "8.8.8.8",
        "os": null,
        "ports": [
            53
        ]
    }
    """)

    def test_getHostNamesFromDict(self):
        result = host_extract.getHostNamesFromDict(self.dictFromJSON)
        self.assertEqual(
            result,
            [
                "dns.google",
            ]
        )
    
    def test_getPortsFromDict(self):
        result = host_extract.getPortsFromDict(self.dictFromJSON)
        self.assertEqual(result, [53])
    
    def test_getCountryCodeFromDict(self):
        result = host_extract.getCountryCodeFromDict(self.dictFromJSON)
        self.assertEqual(result, "US")
    
    def test_getServicesFromDict(self):
        result = host_extract.getServicesFromDict(self.dictFromJSON)
        self.assertEqual(
            result,
            []
        )
    
    def test_getHostInfoFromDict(self):
        result = host_extract.getHostInfoFromDict(self.dictFromJSON)
        self.assertEqual(
            result,
            {
                "ip": "8.8.8.8",
                "hostnames": host_extract.getHostNamesFromDict(self.dictFromJSON),
                "ports": host_extract.getPortsFromDict(self.dictFromJSON),
                "country": host_extract.getCountryCodeFromDict(self.dictFromJSON),
                "services": host_extract.getServicesFromDict(self.dictFromJSON),
            }
        )

class TestExtractShodanInfoFromCroppedShodanOutput(unittest.TestCase):
    dictFromJSON = json.loads("""
    {
        "data": [
            {
            "hash": 4674193,
            "_shodan": {
                "region": "eu",
                "ptr": true,
                "module": "http",
                "id": "0c791bcb-782d-4168-bd37-b76540f11916",
                "options": {},
                "crawler": "bf213bc419cc8491376c12af31e32623c1b6f467"
            },
            "product": "nginx",
            "http": {
                "status": 301,
                "robots_hash": null,
                "redirects": [],
                "securitytxt": null,
                "title": "301 Moved Permanently",
                "sitemap_hash": null,
                "robots": null,
                "server": "nginx/1.9.4",
                "headers_hash": 1258854265,
                "host": "5.9.111.213",
                "location": "/",
                "components": {},
                "html_hash": -1755514192,
                "sitemap": null,
                "securitytxt_hash": null
            },
            "os": null,
            "timestamp": "2023-05-16T13:23:58.464783",
            "isp": "Hetzner Online GmbH",
            "cpe23": [
                "cpe:2.3:a:igor_sysoev:nginx:1.9.4"
            ],
            "cpe": [
                "cpe:/a:igor_sysoev:nginx:1.9.4"
            ],
            "transport": "tcp",
            "asn": "AS24940",
            "hostnames": [
                "karisma.org.co"
            ],
            "location": {
                "city": "N\u00fcrnberg",
                "region_code": "BY",
                "area_code": null,
                "longitude": 11.07752,
                "latitude": 49.45421,
                "country_code": "DE",
                "country_name": "Germany"
            },
            "version": "1.9.4",
            "ip": 84504533,
            "domains": [
                "karisma.org.co"
            ],
            "org": "Hetzner Online GmbH",
            "port": 80,
            "opts": {},
            "ip_str": "5.9.111.213"
        }
        ]
    }
    """)

    def test_getServicesFromDict(self):
        result = host_extract.getServicesFromDict(self.dictFromJSON)
        self.assertEqual(
            result,
            [
                {
                    "service": "nginx",
                    "version": "1.9.4",
                    "cpe": [
                        "cpe:/a:igor_sysoev:nginx:1.9.4"
                    ],
                    "cpe23": [
                        "cpe:2.3:a:igor_sysoev:nginx:1.9.4"
                    ],
                    "timestamp": "2023-05-16T13:23:58.464783",
                    "port": 80,
                },
            ]
        )


if __name__ == "__main__":
    unittest.main()
