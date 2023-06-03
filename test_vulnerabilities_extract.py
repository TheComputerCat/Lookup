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
query2 = '[{"cve": {"id": "CVE-2023-31750", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.003", "lastModified": "2023-05-30T19:17:44.447", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "There privileges."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "HIGH", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "LOW", "baseScore": 6.0, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31750/Linksys_E2000_RCE.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}]'
listQuery1 = json.loads(query1)
listQuery2 = json.loads(query2)

firstCpe = "data/vulny/cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*"
secondCpe = "data/vulny/cpe:2.3:o:microsoft:windows_10:1607"

class TestExtractInfoFromRealShodanOutput(unittest.TestCase):

    firstCVE = listQuery1[0]['cve']
    secondCVE = listQuery1[1]['cve']
    thirdCVE = listQuery2[0]['cve']

    firstVulnData = firstCVE['metrics']['cvssMetricV31'][0]['cvssData']
    secondVulnData = secondCVE['metrics']['cvssMetricV31'][0]['cvssData']
    thirdVulnerabilityData = thirdCVE['metrics']['cvssMetricV31'][0]['cvssData']

    firstVulnDict = {
        "cve": 'CVE-2023-31740',
        "baseScore": 7.2,
        "vector": "NETWORK",
        "complexity": "LOW",
        "authentication": "HIGH",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "MEDIUM",
        "availabilityImpact": "LOW"
    }

    secondVulnDict = {
        "cve": 'CVE-2023-31741',
        "baseScore": 7.1,
        "vector": "LOCAL",
        "complexity": "HIGH",
        "authentication": "LOW",
        "confidentialityImpact": "LOW",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH"
    }

    thirdVulnDict = {
        "cve": 'CVE-2023-31750',
        "baseScore": 6.0,
        "vector": "LOCAL",
        "complexity": "HIGH",
        "authentication": "HIGH",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "LOW"
    }

    cvesDictFromFirstQuery = {
        'CVE-2023-31740': firstVulnDict,
        'CVE-2023-31741': secondVulnDict,
    }

    allCves = {
        'CVE-2023-31740': firstVulnDict,
        'CVE-2023-31741': secondVulnDict,
        'CVE-2023-31750': thirdVulnDict,
    }

    def test_Helpers(self):
        test_cases = [
            ['CVE-2023-31740', vulnerabilities_extract.getCveId(self.firstCVE)],
            ['CVE-2023-31741', vulnerabilities_extract.getCveId(self.secondCVE)],

            [7.2, vulnerabilities_extract.getBaseScore(self.firstVulnData)],
            [7.1, vulnerabilities_extract.getBaseScore(self.secondVulnData)],

            ["NETWORK", vulnerabilities_extract.getAccessVectorScore(self.firstVulnData)],
            ["LOCAL", vulnerabilities_extract.getAccessVectorScore(self.secondVulnData)],

            ["LOW", vulnerabilities_extract.getAccessComplexityScore(self.firstVulnData)],
            ["HIGH", vulnerabilities_extract.getAccessComplexityScore(self.secondVulnData)],

            ["HIGH", vulnerabilities_extract.getAuthenticationRequirement(self.firstVulnData)],
            ["LOW", vulnerabilities_extract.getAuthenticationRequirement(self.secondVulnData)],
            ["HIGH", vulnerabilities_extract.getAuthenticationRequirement(self.firstVulnData)],
            ["LOW", vulnerabilities_extract.getAuthenticationRequirement(self.secondVulnData)],

            ["HIGH", vulnerabilities_extract.getConfidentialityImpact(self.firstVulnData)],
            ["LOW", vulnerabilities_extract.getConfidentialityImpact(self.secondVulnData)],

            ["MEDIUM", vulnerabilities_extract.getIntegrityImpact(self.firstVulnData)],
            ["HIGH", vulnerabilities_extract.getIntegrityImpact(self.secondVulnData)],

            ["LOW", vulnerabilities_extract.getAvailabilityImpact(self.firstVulnData)],
            ["HIGH", vulnerabilities_extract.getAvailabilityImpact(self.secondVulnData)],

            ["3.1", vulnerabilities_extract.getVersion(self.firstVulnData)],
            ["3.1", vulnerabilities_extract.getVersion(self.secondVulnData)],

            [None, vulnerabilities_extract.getAttribute(self.firstVulnData, "hello")],
            [7.2, vulnerabilities_extract.getAttribute(self.firstVulnData, "baseScore")],

            [self.firstVulnDict, vulnerabilities_extract.trimVulnerabilityInfo(self.firstCVE, 'cvssMetricV31')],
            [self.secondVulnDict, vulnerabilities_extract.trimVulnerabilityInfo(self.secondCVE, 'cvssMetricV31')],
            [self.thirdVulnDict, vulnerabilities_extract.trimVulnerabilityInfo(self.thirdCVE, 'cvssMetricV31')],
            [None, vulnerabilities_extract.trimVulnerabilityInfo(self.firstCVE, 'cvssMetricV2')],

            [self.cvesDictFromFirstQuery, vulnerabilities_extract.getCvesDictFromJson(listQuery1, 'cvssMetricV31')],
        ]

        for result, expected_result in test_cases:
            self.assertEqual(result, expected_result)
    def setXUp(a=None):
        os.makedirs("data/vulny")
        f = common.writeStringToFile(firstCpe, query1)
        g = common.writeStringToFile(secondCpe, query2)
        open(secondCpe).close()

    def tearXDown(a=None):
        os.remove(firstCpe)
        os.remove(secondCpe)
        os.rmdir("data/vulny")

    withAVulnDir = createFixture(setXUp, tearXDown)

    @withAVulnDir()
    def test_completeVulnerabilityTable(self):

        vulnerabilities_extract.getDBSession = MagicMock()
        actual = vulnerabilities_extract.getCvesDictFromAllFilesInDir("data/vulny")

        self.assertEqual(actual, self.allCves)


if __name__ == "__main__":
    unittest.main()
