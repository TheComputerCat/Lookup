import json
from query_manager import getDBSession
from common import (
    getFilePathsInDirectory,
    getStringFromFile,
)
from model import (
    Vulnerability,
    Service,
)

THIRD_VERSION = "3.1"


def completeVulnerabilityTable(vulnDirPath):
    session = getDBSession()
    cveList = getCvesDictFromAllFilesInDir(vulnDirPath)
    for cve_code in cveList.values():
        saveCve(cve_code, session)

    session.commit()
    session.close()


def saveCve(cve, session):
    vulnObject = Vulnerability(**cve)
    session.add(vulnObject)
    #completeObjectInfo(vulnObject, cve)
    session.commit()

def getCvesDictFromAllFilesInDir(vulnDirPath):
    dir = getFilePathsInDirectory(vulnDirPath)
    dict = {}
    for filePath in dir:
        queryString = getStringFromFile(filePath)
        dict |= getCvesDictFromJson(json.loads(queryString), 'cvssMetricV31')
    return dict


def getCvesDictFromJson(query, cveVersion):
    dict = {}
    for cve in query:
        vuln = trimVulnerabilityInfo(cve['cve'], cveVersion)
        dict |= {vuln['cve_code']: vuln}
    return dict


def trimVulnerabilityInfo(cve, version):
    cveScoreFromVersion = getAttribute(cve['metrics'], version)
    if cveScoreFromVersion == None:
        return
    cveScoring = cveScoreFromVersion[0]['cvssData']

    service = {
        "id": 0,
        "name": "hello",
        "cpe_code": "bye"
    }
    return {
        "cve_code": getCveId(cve),
        "service_id": 0,
        "score": getBaseScore(cveScoring),
        "access_vector": getAccessVectorScore(cveScoring),
        "access_complexity": getAccessComplexityScore(cveScoring),
        "authentication_requirement": getAuthenticationRequirement(cveScoring),
        "confidentiality_impact": getConfidentialityImpact(cveScoring),
        "integrity_impact": getIntegrityImpact(cveScoring),
        "availability_impact": getAvailabilityImpact(cveScoring),
        "service": Service(name="hi", cpe_code= "bye"),
    }

def getAttribute(element, attribute):
    return element.get(attribute)

def getCveId(cve):
    return getAttribute(cve, 'id')

def getVersion(cveScoring):
    return getAttribute(cveScoring, 'version')

def getBaseScore(cveScoring):
    if getVersion(cveScoring) == THIRD_VERSION:
        return getAttribute(cveScoring, 'baseScore')

def getAccessVectorScore(cveScoring):
    if getVersion(cveScoring) == THIRD_VERSION:
        return getAttribute(cveScoring, 'attackVector')

def getAccessComplexityScore(cveScoring):
    if getVersion(cveScoring) == THIRD_VERSION:
        return getAttribute(cveScoring, 'attackComplexity')

def getAuthenticationRequirement(cveScoring):
    if getVersion(cveScoring) == THIRD_VERSION:
        return getAttribute(cveScoring, 'privilegesRequired')

def getConfidentialityImpact(cveScoring):
    if getVersion(cveScoring) == THIRD_VERSION:
        return getAttribute(cveScoring, 'confidentialityImpact')

def getIntegrityImpact(cveScoring):
    if getVersion(cveScoring) == THIRD_VERSION:
        return getAttribute(cveScoring, 'integrityImpact')

def getAvailabilityImpact(cveScoring):
    return getAttribute(cveScoring, 'availabilityImpact')
