import vulnerabilities_lookup
import json
import unittest
import time
from unittest.mock import (
    Mock,
    patch,
    call,
)

result1 = """
{
    "resultsPerPage": 1, 
    "startIndex": 0,
    "totalResults": 2,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2020-05-01T18:46:38.947",
    "vulnerabilities": [        
        {
            "cve": {
                "id": "CVE-2013-3900",
                "sourceIdentifier": "secure@microsoft.com",
                "published": "2013-12-11T00:55:03.693",
                "lastModified": "2022-11-02T15:15:43.850",
                "vulnStatus": "Analyzed",
                "cisaExploitAdd": "2022-01-10",
                "cisaActionDue": "2022-07-10",
                "cisaRequiredAction": "Apply updates per vendor instructions.",
                "cisaVulnerabilityName": "Microsoft WinVerifyTrust function Remote Code Execution",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": ""
                    },
                    {
                        "lang": "es",
                        "value": ""
                    }
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:H/Au:N/C:C/I:C/A:C",
                                "accessVector": "NETWORK",
                                "accessComplexity": "HIGH",
                                "authentication": "NONE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "COMPLETE",
                                "availabilityImpact": "COMPLETE",
                                "baseScore": 7.6
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 4.9,
                            "impactScore": 10.0,
                            "acInsufInfo": false,
                            "obtainAllPrivilege": false,
                            "obtainUserPrivilege": false,
                            "obtainOtherPrivilege": false,
                            "userInteractionRequired": true
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-20"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "21540673-614A-4D40-8BD7-3F07723803B0"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:microsoft:windows_10:20h2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9E2C378B-1507-4C81-82F6-9F599616845A"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://blogs.technet.com/b/srd/archive/2013/12/10/ms13-098-update-to-enhance-the-security-of-authenticode.aspx",
                        "source": "secure@microsoft.com",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-098",
                        "source": "secure@microsoft.com",
                        "tags": [
                            "Patch",
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        }
    ]
}"""

result2 = """
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 2,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2020-05-01T18:46:38.947",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2015-6184",
                "sourceIdentifier": "secure@microsoft.com",
                "published": "2016-03-09T23:59:00.163",
                "lastModified": "2018-10-12T22:10:41.470",
                "vulnStatus": "Modified",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": ""
                    },
                    {
                        "lang": "es",
                        "value": ""
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "HIGH",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH"
                            },
                            "exploitabilityScore": 2.2,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                "accessVector": "NETWORK",
                                "accessComplexity": "MEDIUM",
                                "authentication": "NONE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "COMPLETE",
                                "availabilityImpact": "COMPLETE",
                                "baseScore": 9.3
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 8.6,
                            "impactScore": 10.0,
                            "acInsufInfo": false,
                            "obtainAllPrivilege": false,
                            "obtainUserPrivilege": false,
                            "obtainOtherPrivilege": false
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "NVD-CWE-Other"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:microsoft:internet_explorer:7:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1A33FA7F-BB2A-4C66-B608-72997A2BD1DB"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:microsoft:internet_explorer:8:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "A52E757F-9B41-43B4-9D67-3FEDACA71283"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "15BAAA8C-7AF1-46CE-9FFB-3A498508A1BF"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "FBC814B4-7DEC-4EFC-ABFF-08FFD9FD16AA"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-106",
                        "source": "secure@microsoft.com"
                    },
                    {
                        "url": "https://www.verisign.com/en_US/security-services/security-intelligence/vulnerability-reports/articles/index.xhtml?id=1218",
                        "source": "secure@microsoft.com"
                    }
                ]
            }
        }
    ]
}
"""

first_page = json.loads(result1)
second_page = json.loads(result2)
cpeCode = "cpe:2.3:o:microsoft:windows_10:1607"

def side_effect(code, startIndex = 0):
    if code != cpeCode:
        return
    if startIndex == 0:
        return first_page
    if startIndex == 1:
        return second_page


class Test(unittest.TestCase):
    @patch("time.sleep")
    def test_cpeIsQueried(self, timeMock):
        vulnerabilities_lookup.queryProduct = Mock(side_effect=side_effect)
        vulnerabilities_lookup.queryCPE = Mock(side_effect=side_effect)
        cpeCode = "cpe:2.3:o:microsoft:windows_10:1607"

        vulnerabilities_lookup.saveVulnerabilitiesFrom(cpeCode)

        vulnerabilities_lookup.queryCPE.assert_called_once_with(cpeCode)
        vulnerabilities_lookup.queryProduct.assert_called_once_with(cpeCode, 1)


if __name__ == "__main__":
    unittest.main()
