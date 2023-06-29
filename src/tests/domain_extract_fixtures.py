import src.common.model as model

from datetime import datetime

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
            'value': '192.0.0.1',
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
            'value': 'v=DMARC1; p=none',
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
                'value': '192.0.0.1',
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
                'value': 'v=DMARC1; p=none',
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
            'value': '192.0.0.2',
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
            'value': 'v=DMARC1; p=none',
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
                'value': '192.0.0.2',
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
                'value': 'v=DMARC1; p=none',
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
                'value': '192.0.0.1',
                'last_seen': '1996-05-23T15:17:24.000000',
            },
            {   
                'subdomain': 'sub1',
                'ports': [
                    21,
                    27,
                ],
                'value': '192.0.0.2',
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
                'value': 'v=DMARC1; p=none',
                'last_seen': '1996-05-23T15:17:24.000000',
            },
            {
                'subdomain': '_dmarc',
                'value': 'v=DMARC1; p=none',
                'last_seen': '1992-05-23T15:17:24.000000',
            }
        ]
    }
}

filteredShodanJson1WithObjects = {
    'main_domain': model.MainDomain(id=None, name='domain.org', organization_id=None), 
    'main_domain_info': model.DomainInfo(domain='', id=None, main_domain_id=None, subdomain=False),
    'main': {
        'A': [
            model.ARecord(id=None, ip_address='192.168.1.1', parent_domain_info_id=None, timestamp=datetime(1991, 5, 17, 7, 53, 21)),
            model.ARecord(id=None, ip_address='172.132.16.77', parent_domain_info_id=None, timestamp=datetime(2011, 5, 17, 1, 26, 37))
        ], 
        'MX': [
            model.MXRecord(domain='mail.domain.org', id=None, parent_domain_info_id=None, timestamp=datetime(1991, 5, 23, 15, 17, 24)), 
            model.MXRecord(domain='mail2.domain.org', id=None, parent_domain_info_id=None, timestamp=datetime(1992, 5, 23, 15, 17, 24))
        ], 
        'TXT': [
            model.TXTRecord(content='v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all', id=None, parent_domain_info_id=None, timestamp=datetime(2023, 5, 23, 15, 11, 10))
        ]
    }, 
    'subdomains': {
        'A': [
                {
                    'subdomain': model.DomainInfo(domain='sub1', id=None, main_domain_id=None, subdomain=True),
                    'info': model.ARecord(id=None, ip_address='192.0.0.1', parent_domain_info_id=None, timestamp=datetime(1996, 5, 23, 15, 17, 24))
                }
        ], 
        'MX': [
            {
                'subdomain': model.DomainInfo(domain='sub2', id=None, main_domain_id=None, subdomain=True), 
                'info': model.MXRecord(domain='sub2.domain.org', id=None, parent_domain_info_id=None, timestamp=datetime(1996, 5, 23, 15, 17, 24))
            }
        ], 
        'TXT': [
            {
                'subdomain': model.DomainInfo(domain='_dmarc', id=None, main_domain_id=None, subdomain=True), 
                'info': model.TXTRecord(content='v=DMARC1; p=none', id=None, parent_domain_info_id=None, timestamp=datetime(1996, 5, 23, 15, 17, 24))
            }
        ]
    }, 
}


