import json
import query_manager
from query_manager import (
    getDBSession,
    searchInTable,
)
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
    directory = getFilePathsInDirectory(vulnDirPath)
    cveList = []
    for filePath in directory:
        cpeCode = filePath.split("/")[-1]
        queryString = getStringFromFile(filePath)
        newList = getCvesDictFromJson(json.loads(queryString), cpeCode, 'cvssMetricV31')
        cveList.extend(newList)
    return cveList


def getCvesDictFromJson(query, cpeCode, cveVersion):
    list = []
    for cve in query:
        vuln = trimVulnerabilityInfo(cve['cve'], cpeCode, cveVersion)
        list.append(vuln)
    return list


def trimVulnerabilityInfo(cve, cpeCode, version):
    cveScoreFromVersion = getAttribute(cve['metrics'], version)
    if cveScoreFromVersion is None:
        return

    cveScoring = cveScoreFromVersion[0]['cvssData']
    service = searchInTable(Service, {"cpe_code": cpeCode})

    return {
        "cve_code": getCveId(cve),
        "service_id": service.id,
        "score": getBaseScore(cveScoring),
        "access_vector": getAccessVectorScore(cveScoring),
        "access_complexity": getAccessComplexityScore(cveScoring),
        "authentication_requirement": getAuthenticationRequirement(cveScoring),
        "confidentiality_impact": getConfidentialityImpact(cveScoring),
        "integrity_impact": getIntegrityImpact(cveScoring),
        "availability_impact": getAvailabilityImpact(cveScoring),
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
