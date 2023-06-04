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

SECOND_VERSION = "2.0"
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

    if getVersion(cveScoring) == SECOND_VERSION:
        return getV2Dict(cveScoring, cve, service)
    if getVersion(cveScoring) == THIRD_VERSION:
        return getV31Dict(cveScoring, cve, service)

def getAttribute(element, attribute):
    return element.get(attribute)

def getVersion(cveScoring):
    return getAttribute(cveScoring, 'version')

def getV2Dict(cveScoring, cve, service):
    return {
            "cve_code": getAttribute(cve, 'id'),
            "service_id": service.id,
            "score": getAttribute(cveScoring, 'baseScore'),
            "access_vector": getAttribute(cveScoring, 'accessVector'),
            "access_complexity": getAttribute(cveScoring, 'accessComplexity'),
            "authentication_requirement": getAttribute(cveScoring, 'authentication'),
            "confidentiality_impact": getAttribute(cveScoring, 'confidentialityImpact'),
            "integrity_impact": getAttribute(cveScoring, 'integrityImpact'),
            "availability_impact": getAttribute(cveScoring, 'availabilityImpact'),
        }

def getV31Dict(cveScoring, cve, service):
    return {
        "cve_code": getAttribute(cve, 'id'),
        "service_id": service.id,
        "score": getAttribute(cveScoring, 'baseScore'),
        "access_vector": getAttribute(cveScoring, 'attackVector'),
        "access_complexity": getAttribute(cveScoring, 'attackComplexity'),
        "authentication_requirement": getAttribute(cveScoring, 'privilegesRequired'),
        "confidentiality_impact": getAttribute(cveScoring, 'confidentialityImpact'),
        "integrity_impact": getAttribute(cveScoring, 'integrityImpact'),
        "availability_impact": getAttribute(cveScoring, 'availabilityImpact'),
    }