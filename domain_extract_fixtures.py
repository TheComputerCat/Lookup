shodanJson1 = {
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
    'more': True,
}
filteredShodanJson1 = {
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

shodanJson2 = {
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
            'last_seen': '1992-05-17T07:53:21.000000'
        },
        {
            'subdomain': '',
            'type': 'MX',
            'value': 'mail.domain.org',
            'last_seen': '1993-05-23T15:17:24.000000'
        },
        {
            "subdomain": "",
            "type": "TXT",
            "value": "v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all",
            "last_seen": "2021-05-23T15:11:10.584000"
        },
        {
            'subdomain': 'sub1',
            'type': 'A',
            "ports": [
                21,
                27,
            ],
            'value': 'sub1.domain.org',
            'last_seen': '1998-05-23T15:17:24.000000'
        },
        {
            'subdomain': 'sub2',
            'type': 'MX',
            'value': 'sub2.domain.org',
            'last_seen': '1991-05-23T15:17:24.000000'
        },
        {
            'subdomain': '_dmarc',
            'type': 'TXT',
            'value': 'v=DMARC1; p=none"',
            'last_seen': '1992-05-23T15:17:24.000000',
        }
    ],
    'more': False,
}
filteredShodanJson2 = {
    'domain': 'domain.org',
    'main' :{
        'A':[
            {
                'ports': [
                    2222
                ],
                'value': '192.168.1.1',
                'last_seen': '1992-05-17T07:53:21.000000',
                
            }
        ],
        'MX': [
            {
                'value': 'mail.domain.org',
                'last_seen': '1993-05-23T15:17:24.000000'
            }
        ],
        'TXT':[
            {
                "value": "v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all",
                "last_seen": "2021-05-23T15:11:10.584000"
            }
        ]
    },
    'subdomains': {
        'A':[
            {   
                'subdomain': 'sub1',
                'ports': [
                    21,
                    27,
                ],
                'value': 'sub1.domain.org',
                'last_seen': '1998-05-23T15:17:24.000000',
            }
        ],
        'MX': [
            {
                'subdomain': 'sub2',
                'value': 'sub2.domain.org',
                'last_seen': '1991-05-23T15:17:24.000000',
            }
        ],
        'TXT': [
            {
                'subdomain': '_dmarc',
                'value': 'v=DMARC1; p=none"',
                'last_seen': '1992-05-23T15:17:24.000000',
            }
        ]
    }
}

filteredJoinedShodanJson1AndJson2 = {
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
            },
            {
                'ports': [
                    2222
                ],
                'value': '192.168.1.1',
                'last_seen': '1992-05-17T07:53:21.000000',
                
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
            },
            {
                'value': 'mail.domain.org',
                'last_seen': '1993-05-23T15:17:24.000000'
            }
        ],
        'TXT':[
            {
                "value": "v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all",
                "last_seen": "2023-05-23T15:11:10.584000"
            },
            {
                "value": "v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all",
                "last_seen": "2021-05-23T15:11:10.584000"
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
            },
            {   
                'subdomain': 'sub1',
                'ports': [
                    21,
                    27,
                ],
                'value': 'sub1.domain.org',
                'last_seen': '1998-05-23T15:17:24.000000',
            }
        ],
        'MX': [
            {
                'subdomain': 'sub2',
                'value': 'sub2.domain.org',
                'last_seen': '1996-05-23T15:17:24.000000',
            },
            {
                'subdomain': 'sub2',
                'value': 'sub2.domain.org',
                'last_seen': '1991-05-23T15:17:24.000000',
            }
        ],
        'TXT': [
            {
                'subdomain': '_dmarc',
                'value': 'v=DMARC1; p=none"',
                'last_seen': '1996-05-23T15:17:24.000000',
            },
            {
                'subdomain': '_dmarc',
                'value': 'v=DMARC1; p=none"',
                'last_seen': '1992-05-23T15:17:24.000000',
            }
        ]
    }
}

