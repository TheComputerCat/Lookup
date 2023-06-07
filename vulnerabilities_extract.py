import json
import sys
import query_manager
from query_manager import (
    getDBSession,
    searchInTable,
    setConfigFile,
)
from common import (
    getFilePathsInDirectory,
    getStringFromFile,
    formatDirPath,
)
from model import (
    Vulnerability,
    Service,
)

SECOND_VERSION = "2.0"
THIRD_VERSION = "3.1"


def completeVulnerabilityTable(vulnDirPath, cveVersion):
    session = getDBSession()
    cveList = getVulnDictFromAllFilesInDir(vulnDirPath, cveVersion)
    for cve_code in cveList:
        saveCve(cve_code, session)

    session.commit()
    session.close()


def saveCve(cve, session):
    vulnObject = Vulnerability(**cve)

    session.add(vulnObject)
    session.commit()

def getServiceVulnRelation(cpeCode, cveCode):
    service = searchInTable(Service, {"cpe_code": cpeCode})
    vuln = searchInTable(Vulnerability, {"cve_code": cveCode})

    return {"service_id": service.id, "vulnerability_id": vuln.id}

def getVulnDictFromAllFilesInDir(vulnDirPath, cveVersion):
    directory = getFilePathsInDirectory(vulnDirPath)
    vulnOfService = {}
    for filePath in directory:
        file = filePath.split("/")[-1]
        cpeCode = file.rsplit("_", 1)[0]
        queryString = getStringFromFile(filePath)

        vulnOfService[cpeCode] = getVulnDictFromJson(json.loads(queryString), cpeCode, cveVersion)
    return vulnOfService

def getVulnDictFromJson(query, cpeCode, cveVersion):
    list = []
    for cve in query:
        vuln = trimVulnerabilityInfo(cve['cve'], cpeCode, cveVersion)
        if vuln is not None:
            list.append(vuln)
    return list


def trimVulnerabilityInfo(cve, cpeCode, version):
    cveScoreFromVersion = getAttribute(cve['metrics'], version)
    service = searchInTable(Service, {"cpe_code": cpeCode})
    if cveScoreFromVersion is None:
        return emptyVDict(cve, service)

    cveScoring = cveScoreFromVersion[0]['cvssData']

    if getVersion(cveScoring) == SECOND_VERSION:
        return getV2Dict(cveScoring, cve, service)
    if getVersion(cveScoring) == THIRD_VERSION:
        return getV31Dict(cveScoring, cve, service)

def getVersion(cveScoring):
    return getAttribute(cveScoring, 'version')

def emptyVDict(cve, service):
    return setupVulnDict(getAttribute(cve, 'id'), None, None, None, None, None, None, None)

def getV2Dict(cveScoring, cve, service):
    return setupVulnDict(
            getAttribute(cve, 'id'),
            getAttribute(cveScoring, 'baseScore'),
            getAttribute(cveScoring, 'accessVector'),
            getAttribute(cveScoring, 'accessComplexity'),
            getAttribute(cveScoring, 'authentication'),
            getAttribute(cveScoring, 'confidentialityImpact'),
            getAttribute(cveScoring, 'integrityImpact'),
            getAttribute(cveScoring, 'availabilityImpact'),
        )

def getV31Dict(cveScoring, cve, service):
    return setupVulnDict(
        getAttribute(cve, 'id'),
        getAttribute(cveScoring, 'baseScore'),
        getAttribute(cveScoring, 'attackVector'),
        getAttribute(cveScoring, 'attackComplexity'),
        getAttribute(cveScoring, 'privilegesRequired'),
        getAttribute(cveScoring, 'confidentialityImpact'),
        getAttribute(cveScoring, 'integrityImpact'),
        getAttribute(cveScoring, 'availabilityImpact')
    )

def getAttribute(element, attribute):
    return element.get(attribute)

def setupVulnDict(cve_cove, score, access_vector, access_complexity, authentication_requirement, confidentiality_impact, integrity_impact, availability_impact):
    return {
        "cve_code": cve_cove,
        "score": score,
        "access_vector": access_vector,
        "access_complexity": access_complexity,
        "authentication_requirement": authentication_requirement,
        "confidentiality_impact": confidentiality_impact,
        "integrity_impact": integrity_impact,
        "availability_impact": availability_impact,
    }


if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) < 3:
        raise Exception("""Se necesitan tres argumentos:
    1. La ruta al archivo con las credenciales de la base de datos,
    2. La ruta al directorio con la información de las vulnerabilidades,
    3. La version de metrica de CVE a recolectar (cvssMetricV2 o cvssMetricV31).""")

    configFile = args[0]
    vulnDir = formatDirPath(args[1])
    cvssVersion = args[2]

    setConfigFile(configFile)
    completeVulnerabilityTable(vulnDir, cvssVersion)
