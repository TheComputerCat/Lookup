import vulnerabilities_extract
import json
import unittest

savedVulnerabilitiesQuery = json.loads('[{"cve": {"id": "CVE-2023-31740", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.003", "lastModified": "2023-05-30T19:17:44.447", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "There is a command injection vulnerability in the Linksys E2000 router with firmware version 1.0.06. If an attacker gains web management privileges, they can inject commands into the post request parameters WL_atten_bb, WL_atten_radio, and WL_atten_ctl in the apply.cgi interface, thereby gaining shell privileges."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "HIGH", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "MEDIUM", "availabilityImpact": "LOW", "baseScore": 7.2, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31740/Linksys_E2000_RCE.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}, {"cve": {"id": "CVE-2023-31741", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.047", "lastModified": "2023-05-31T00:26:35.690", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "There is a command injection vulnerability in the Linksys E2000 router with firmware version 1.0.06. If an attacker gains web management privileges, they can inject commands into the post request parameters wl_ssid, wl_ant, wl_rate, WL_atten_ctl, ttcp_num, ttcp_size in the httpd s Start_EPI() function, thereby gaining shell privileges."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 7.1, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31741/Linksys_E2000_RCE_2.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}]')

"""
  id
x cve
x score
  servicio
x accessVector
x accessComplexity
x authenticationRequirement
  confidentialityImpact
  integrityImpact
  availabilityImpact'
"""

class TestExtractInfoFromRealShodanOutput(unittest.TestCase):
    def test_Helpers(self):
        firstCVE = savedVulnerabilitiesQuery[0]['cve']
        secondCVE = savedVulnerabilitiesQuery[1]['cve']

        firstVulnerabilityData = firstCVE['metrics']['cvssMetricV31'][0]['cvssData']
        secondVulnerabilityData = secondCVE['metrics']['cvssMetricV31'][0]['cvssData']

        test_cases = [
            ['CVE-2023-31740', vulnerabilities_extract.getCveId(firstCVE)],
            ['CVE-2023-31741', vulnerabilities_extract.getCveId(secondCVE)],
            [7.2, vulnerabilities_extract.getBaseScore(firstVulnerabilityData)],
            [7.1, vulnerabilities_extract.getBaseScore(secondVulnerabilityData)],
            ["NETWORK", vulnerabilities_extract.getAccessVectorScore(firstVulnerabilityData)],
            ["LOCAL", vulnerabilities_extract.getAccessVectorScore(secondVulnerabilityData)],
            ["LOW", vulnerabilities_extract.getAccessComplexityScore(firstVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getAccessComplexityScore(secondVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getAuthenticationRequirement(firstVulnerabilityData)],
            ["LOW", vulnerabilities_extract.getAuthenticationRequirement(secondVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getAuthenticationRequirement(firstVulnerabilityData)],
            ["LOW", vulnerabilities_extract.getAuthenticationRequirement(secondVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getConfidentialityImpact(firstVulnerabilityData)],
            ["LOW", vulnerabilities_extract.getConfidentialityImpact(secondVulnerabilityData)],
            ["MEDIUM", vulnerabilities_extract.getIntegrityImpact(firstVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getIntegrityImpact(secondVulnerabilityData)],
            ["LOW", vulnerabilities_extract.getAvailabilityImpact(firstVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getAvailabilityImpact(secondVulnerabilityData)],
            ["3.1", vulnerabilities_extract.getVersion(firstVulnerabilityData)],
            ["3.1", vulnerabilities_extract.getVersion(secondVulnerabilityData)],
            ["HIGH", vulnerabilities_extract.getAvailabilityImpact(secondVulnerabilityData)],
            [None, vulnerabilities_extract.getAttribute(firstVulnerabilityData, "hello")],
            [7.2, vulnerabilities_extract.getAttribute(firstVulnerabilityData, "baseScore")],
        ]

        for result, expected_result in test_cases:
            self.assertEqual(result, expected_result)

if __name__ == "__main__":
    unittest.main()
