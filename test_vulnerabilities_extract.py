import os
import vulnerabilities_extract
import json
import unittest
import model
from vulnerabilities_extract import setupVulnDict

from sqlalchemy import create_engine
from testcontainers.postgres import PostgresContainer
import query_manager

from unittest.mock import (
    patch,
    MagicMock,
)
from common import (
    writeStringToFile,
    createFixture,
)
from query_manager import (
    Service,
    Vulnerability,
    ServiceVulnerability,
)


query1 = '[{"cve": {"id": "CVE-2023-31740", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.003", "lastModified": "2023-05-30T19:17:44.447", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "There privileges."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "HIGH", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "MEDIUM", "availabilityImpact": "LOW", "baseScore": 7.2, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31740/Linksys_E2000_RCE.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}, {"cve": {"id": "CVE-2023-31741", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.047", "lastModified": "2023-05-31T00:26:35.690", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "blah blah."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 7.1, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31741/Linksys_E2000_RCE_2.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}]'
query2 = '[{"cve": {"id": "CVE-2023-31741", "sourceIdentifier": "cve@mitre.org", "published": "2023-05-23T01:15:10.047", "lastModified": "2023-05-31T00:26:35.690", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "blah blah."}], "metrics": {"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:H/Au:N/C:C/I:C/A:C", "accessVector": "NETWORK", "accessComplexity": "HIGH", "authentication": "NONE", "confidentialityImpact": "COMPLETE", "integrityImpact": "COMPLETE", "availabilityImpact": "COMPLETE", "baseScore": 7.6}, "baseSeverity": "HIGH", "exploitabilityScore": 4.9, "impactScore": 10.0, "acInsufInfo": false, "obtainAllPrivilege": false, "obtainUserPrivilege": false, "obtainOtherPrivilege": false, "userInteractionRequired": true}],"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 7.1, "baseSeverity": "HIGH"}, "exploitabilityScore": 1.2, "impactScore": 5.9}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}], "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*", "matchCriteriaId": "FE947E51-AD41-462E-B0B6-69A21F7D670A"}]}, {"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:h:linksys:e2000:-:*:*:*:*:*:*:*", "matchCriteriaId": "8052B407-172A-4A6B-983C-074F0FD1F8DB"}]}]}], "references": [{"url": "http://linksys.com", "source": "cve@mitre.org", "tags": ["Product"]}, {"url": "https://github.com/D2y6p/CVE/blob/main/Linksys/CVE-2023-31741/Linksys_E2000_RCE_2.pdf", "source": "cve@mitre.org", "tags": ["Exploit", "Mitigation", "Third Party Advisory"]}]}}]'

listQuery1 = json.loads(query1)
listQuery2 = json.loads(query2)

firstCpe = "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*"
secondCpe = "cpe:2.3:o:microsoft:windows_10:1607"

firstCpePath = "data/vulny/cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*_-2023:06:03-17:03:05"
secondCpePath = "data/vulny/cpe:2.3:o:microsoft:windows_10:1607_-2023:06:03-17:02:57"

temporalVulnerabilityDir = "data/vulny"

def searchMock():
    class DatabaseObjectMock:
        def __init__(self, table, dict):
            if table == Service:
                cpe_code = dict["cpe_code"]
                if cpe_code == firstCpe:
                    self.id = 0
                elif cpe_code == secondCpe:
                    self.id = 1
                else:
                    raise Exception("cpe {} doesnt exist in mocked DB".format(cpe_code))

            if table == Vulnerability:
                cve_code = dict["cve_code"]
                if cve_code == 'CVE-2023-31740':
                    self.id = 0
                elif cve_code == 'CVE-2023-31741':
                    self.id = 1
                else:
                    raise Exception("cve {} doesnt exist in mocked DB".format(cve_code))

    return lambda a, b: DatabaseObjectMock(a, b)

def setUpVulnDirectory():
    os.makedirs(temporalVulnerabilityDir)
    f = writeStringToFile(firstCpePath, query1)
    g = writeStringToFile(secondCpePath, query2)
    open(secondCpePath).close()

def teardownVulnDirectory():
    os.remove(firstCpePath)
    os.remove(secondCpePath)
    os.rmdir(temporalVulnerabilityDir)

withAVulnDir = createFixture(setUpVulnDirectory, teardownVulnDirectory)


class TestVulnerabilityTable(unittest.TestCase):
    firstCVE = listQuery1[0]['cve']
    secondCVE = listQuery1[1]['cve']
    thirdCVE = listQuery2[0]['cve']

    firstVulnData = firstCVE['metrics']['cvssMetricV31'][0]['cvssData']
    secondVulnData = secondCVE['metrics']['cvssMetricV31'][0]['cvssData']
    thirdVulnDataV31 = thirdCVE['metrics']['cvssMetricV31'][0]['cvssData']
    thirdVulnDataV2 = thirdCVE['metrics']['cvssMetricV2'][0]['cvssData']

    firstVulnDictV31 = {
        "cve_code": 'CVE-2023-31740',
        "score": 7.2,
        "access_vector": "NETWORK",
        "access_complexity": "LOW",
        "authentication_requirement": "HIGH",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "MEDIUM",
        "availability_impact": "LOW",
    }

    secondVulnDictV31 = setupVulnDict('CVE-2023-31741', 7.1, "LOCAL", "HIGH", "LOW", "LOW", "HIGH", "HIGH")
    thirdVulnDictV31 = setupVulnDict('CVE-2023-31741', 7.1, "LOCAL", "HIGH", "LOW", "LOW", "HIGH", "HIGH")

    firstVulnDictV2 = setupVulnDict('CVE-2023-31740', None, None, None, None, None, None, None)
    secondVulnDictV2 = setupVulnDict('CVE-2023-31741', None, None, None, None, None, None, None)
    thirdVulnDictV2 = setupVulnDict('CVE-2023-31741', 7.6, "NETWORK", "HIGH", "NONE", "COMPLETE", "COMPLETE", "COMPLETE")

    cvesDictFromFirstQuery = [
        firstVulnDictV31,
        secondVulnDictV31,
    ]

    @patch("vulnerabilities_extract.searchInTable", new_callable=searchMock)
    def test_Helpers(self, dbMock):
        test_cases = [
            ["3.1", vulnerabilities_extract.getVersion(self.firstVulnData)],
            ["3.1", vulnerabilities_extract.getVersion(self.secondVulnData)],

            [None, vulnerabilities_extract.getAttribute(self.firstVulnData, "hello")],
            [7.2, vulnerabilities_extract.getAttribute(self.firstVulnData, "baseScore")],

            [self.firstVulnDictV31, vulnerabilities_extract.trimVulnerabilityInfo(self.firstCVE, firstCpe, 'cvssMetricV31')],
            [self.secondVulnDictV31, vulnerabilities_extract.trimVulnerabilityInfo(self.secondCVE, firstCpe, 'cvssMetricV31')],
            [self.thirdVulnDictV31, vulnerabilities_extract.trimVulnerabilityInfo(self.thirdCVE, secondCpe, 'cvssMetricV31')],
            [self.firstVulnDictV2, vulnerabilities_extract.trimVulnerabilityInfo(self.firstCVE, firstCpe, 'cvssMetricV2')],
            [self.thirdVulnDictV2, vulnerabilities_extract.trimVulnerabilityInfo(self.thirdCVE, secondCpe, 'cvssMetricV2')],

            [self.cvesDictFromFirstQuery, vulnerabilities_extract.getCvesDictFromJson(listQuery1, firstCpe, 'cvssMetricV31')],
        ]

        for result, expected_result in test_cases:
            self.assertEqual(result, expected_result)

    allCvesForV31 = [
        firstVulnDictV31,
        secondVulnDictV31,
        thirdVulnDictV31,
    ]

    @withAVulnDir()
    @patch("vulnerabilities_extract.searchInTable", new_callable=searchMock)
    def test_completeVulnerabilityTable(self, dbMock):
        actual = vulnerabilities_extract.getCvesDictFromAllFilesInDir(temporalVulnerabilityDir, 'cvssMetricV31')

        self.assertEqual(actual, self.allCvesForV31)

    allCvesForV2 = [
        thirdVulnDictV2,
        firstVulnDictV2,
        secondVulnDictV2,
    ]

    @withAVulnDir()
    @patch("vulnerabilities_extract.searchInTable", new_callable=searchMock)
    def test_completeVulnerabilityTable(self, dbMock):
        actual = vulnerabilities_extract.getCvesDictFromAllFilesInDir(temporalVulnerabilityDir, 'cvssMetricV2')

        self.assertEqual(actual, self.allCvesForV2)

    @withAVulnDir()
    @patch("vulnerabilities_extract.searchInTable", new_callable=searchMock)
    def test_completeVulnerabilityTable(self, dbMock):
        actual = vulnerabilities_extract.getServiceVulnRelation(firstCpe, 'CVE-2023-31741')
        expected = {"service_id": 0, "vulnerability_id": 1}

        self.assertEqual(actual, expected)

def setUpServicesTable():
    session = query_manager.getDBSession()
    service1 = {"id": 0, "name": "linksys", "version": "1.0.06", "cpe_code": "cpe:2.3:o:linksys:e2000_firmware:1.0.06:*:*:*:*:*:*:*"}
    service2 = {"id": 1, "name": "microsoft", "version": "10", "cpe_code": "cpe:2.3:o:microsoft:windows_10:1607"}
    session.add(Service(**service1))
    session.add(Service(**service2))
    session.commit()
    session.close()

def setUpDatabase(postgres):
    postgres.start()
    global actualGetDBEngine
    actualGetDBEngine = query_manager.getDBEngine
    query_manager.getDBEngine = lambda: create_engine(postgres.get_connection_url())

def tearDownDatabase(postgres):
    query_manager.getDBEngine = actualGetDBEngine
    postgres.stop()

withTestDatabase = createFixture(setUpDatabase, tearDownDatabase)


class TestDataBaseInteraction(unittest.TestCase):
    firstVulnDictV31 = {
        "id": 2,
        "cve_code": 'CVE-2023-31740',
        "score": 7.2,
        "access_vector": "NETWORK",
        "access_complexity": "LOW",
        "authentication_requirement": "HIGH",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "MEDIUM",
        "availability_impact": "LOW",
    }

    secondVulnDictV31 = {
        "id": 3,
        "cve_code": 'CVE-2023-31741',
        "score": 7.1,
        "access_vector": "LOCAL",
        "access_complexity": "HIGH",
        "authentication_requirement": "LOW",
        "confidentiality_impact": "LOW",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
    }

    thirdVulnDictV31 = {
        "id": 1,
        "cve_code": 'CVE-2023-31741',
        "score": 7.1,
        "access_vector": "LOCAL",
        "access_complexity": "HIGH",
        "authentication_requirement": "LOW",
        "confidentiality_impact": "LOW",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
    }

    def assertVulnTableIsCorrect(self):
        session = query_manager.getDBSession()
        allVuln = session.query(Vulnerability).all()
        session.close()

        list(map(lambda v: vars(v).pop('_sa_instance_state'), allVuln))

        self.assertEqual(len(allVuln), 3)
        self.assertDictEqual(vars(allVuln[0]), self.thirdVulnDictV31)
        self.assertDictEqual(vars(allVuln[2]), self.secondVulnDictV31)
        self.assertDictEqual(vars(allVuln[1]), self.firstVulnDictV31)

    @withAVulnDir()
    @withTestDatabase(postgres=PostgresContainer("postgres:latest"))
    def test_completeTables(self):
        query_manager.createTables()
        setUpServicesTable()

        cvssVersion = "cvssMetricV31"
        vulnerabilities_extract.completeVulnerabilityTable(temporalVulnerabilityDir, cvssVersion)
        self.assertVulnTableIsCorrect()

if __name__ == "__main__":
    unittest.main()
