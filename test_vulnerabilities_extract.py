import os

import common
import vulnerabilities_extract
import json
import unittest
from unittest.mock import (
    patch,
    MagicMock,
)
from common import (
    setUpWithATextFile,
    tearDownWithATextFile,
    createFixture,
)

query1 = '[{"cve": {"id": "CVE-2023-31740", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.003", "lastModified": "2023-05-30T19:17:44.447", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "There privileges."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "HIGH", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "MEDIUM", "availabilityImpact": "LOW", "baseScore": 7.2, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31740/Linksys_E2000_RCE.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}, {"cve": {"id": "CVE-2023-31741", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.047", "lastModified": "2023-05-31T00:26:35.690", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "blah blah."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 7.1, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31741/Linksys_E2000_RCE_2.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}]'
query2 = '[{"cve": {"id": "CVE-2023-31741", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.047", "lastModified": "2023-05-31T00:26:35.690", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "blah blah."}], "metrics": {"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:H/Au:N/C:C/I:C/A:C", "accessVector": "NETWORK", "accessComplexity": "HIGH", "authentication": "NONE", "confidentialityImpact": "COMPLETE", "integrityImpact": "COMPLETE", "availabilityImpact": "COMPLETE", "baseScore": 7.6}, "baseSeverity": "HIGH", "exploitabilityScore": 4.9, "impactScore": 10.0, "acInsufInfo": false, "obtainAllPrivilege": false, "obtainUserPrivilege": false, "obtainOtherPrivilege": false, "userInteractionRequired": true}],"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 7.1, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31741/Linksys_E2000_RCE_2.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}]'

listQuery1 = json.loads(query1)
listQuery2 = json.loads(query2)

firstCpe = "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*"
secondCpe = "cpe:2.3:o:microsoft:windows_10:1607"

firstCpePath = "data/vulny/cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*"
secondCpePath = "data/vulny/cpe:2.3:o:microsoft:windows_10:1607"


def searchMock():
    class ServiceMock:
        def __init__(self, cpe):
            if cpe == firstCpe:
                self.id = 0
            elif cpe == secondCpe:
                self.id = 1

    return lambda a, b: ServiceMock(b["cpe_code"])


class TestExtractInfoFromRealShodanOutput(unittest.TestCase):
    firstCVE = listQuery1[0]['cve']
    secondCVE = listQuery1[1]['cve']
    thirdCVE = listQuery2[0]['cve']

    firstVulnData = firstCVE['metrics']['cvssMetricV31'][0]['cvssData']
    secondVulnData = secondCVE['metrics']['cvssMetricV31'][0]['cvssData']
    thirdVulnDataV31 = thirdCVE['metrics']['cvssMetricV31'][0]['cvssData']
    thirdVulnDataV2 = thirdCVE['metrics']['cvssMetricV2'][0]['cvssData']

    firstVulnDict = {
        "cve_code": 'CVE-2023-31740',
        "service_id": 0,
        "score": 7.2,
        "access_vector": "NETWORK",
        "access_complexity": "LOW",
        "authentication_requirement": "HIGH",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "MEDIUM",
        "availability_impact": "LOW",
    }

    secondVulnDict = {
        "cve_code": 'CVE-2023-31741',
        "service_id": 0,
        "score": 7.1,
        "access_vector": "LOCAL",
        "access_complexity": "HIGH",
        "authentication_requirement": "LOW",
        "confidentiality_impact": "LOW",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
    }

    thirdVulnDictV31 = {
        "cve_code": 'CVE-2023-31741',
        "service_id": 1,
        "score": 7.1,
        "access_vector": "LOCAL",
        "access_complexity": "HIGH",
        "authentication_requirement": "LOW",
        "confidentiality_impact": "LOW",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
    }

    thirdVulnDictV2 = {
        "cve_code": 'CVE-2023-31741',
        "service_id": 1,
        "score": 7.6,
        "access_vector": "NETWORK",
        "access_complexity": "HIGH",
        "authentication_requirement": "NONE",
        "confidentiality_impact": "COMPLETE",
        "integrity_impact": "COMPLETE",
        "availability_impact": "COMPLETE",
    }

    cvesDictFromFirstQuery = [
        firstVulnDict,
        secondVulnDict,
    ]

    allCves = [
        firstVulnDict,
        secondVulnDict,
        thirdVulnDictV31,
    ]

    @patch("vulnerabilities_extract.searchInTable", new_callable=searchMock)
    def test_Helpers(self, dbMock):
        test_cases = [
            ["3.1", vulnerabilities_extract.getVersion(self.firstVulnData)],
            ["3.1", vulnerabilities_extract.getVersion(self.secondVulnData)],

            [None, vulnerabilities_extract.getAttribute(self.firstVulnData, "hello")],
            [7.2, vulnerabilities_extract.getAttribute(self.firstVulnData, "baseScore")],

            [self.firstVulnDict, vulnerabilities_extract.trimVulnerabilityInfo(self.firstCVE, firstCpe, 'cvssMetricV31')],
            [self.secondVulnDict, vulnerabilities_extract.trimVulnerabilityInfo(self.secondCVE, firstCpe, 'cvssMetricV31')],
            [self.thirdVulnDictV31, vulnerabilities_extract.trimVulnerabilityInfo(self.thirdCVE, secondCpe, 'cvssMetricV31')],
            [self.thirdVulnDictV2, vulnerabilities_extract.trimVulnerabilityInfo(self.thirdCVE, secondCpe, 'cvssMetricV2')],
            [None, vulnerabilities_extract.trimVulnerabilityInfo(self.firstCVE, firstCpe, 'cvssMetricV2')],

            [self.cvesDictFromFirstQuery, vulnerabilities_extract.getCvesDictFromJson(listQuery1, firstCpe, 'cvssMetricV31')],
        ]

        for result, expected_result in test_cases:
            self.assertEqual(result, expected_result)

    def setXUp(a=None):
        os.makedirs("data/vulny")
        f = common.writeStringToFile(firstCpePath, query1)
        g = common.writeStringToFile(secondCpePath, query2)
        open(secondCpePath).close()

    def tearXDown(a=None):
        os.remove(firstCpePath)
        os.remove(secondCpePath)
        os.rmdir("data/vulny")

    withAVulnDir = createFixture(setXUp, tearXDown)

    @withAVulnDir()
    @patch("vulnerabilities_extract.searchInTable", new_callable=searchMock)
    def test_completeVulnerabilityTable(self, dbMock):
        actual = vulnerabilities_extract.getCvesDictFromAllFilesInDir("data/vulny")

        self.assertEqual(actual, self.allCves)


if __name__ == "__main__":
    unittest.main()
