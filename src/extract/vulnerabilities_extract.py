import json
import sys

from src.common.query_manager import (
    getDBSession,
    searchInTable,
    setConfigFile,
)
from src.common.common import (
    getFilePathsInDirectory,
    getStringFromFile,
    formatDirPath,
    log,
)
from src.common.model import (
    Vulnerability,
    Service,
    ServiceVulnerability,
)

SECOND_VERSION = "2.0"
THIRD_VERSION = "3.1"

def completeVulnerabilityTable(vulnDirPath, cveVersion):
    session = getDBSession()
    vulnerabilitiesPerService = getVulnDictFromAllFilesInDir(vulnDirPath, cveVersion)
    for service, vulnerabilityList in vulnerabilitiesPerService.items():
        for vulnerability in vulnerabilityList:
            saveVulnerability(vulnerability, session)
            saveRelation(service, vulnerability, session)

    session.commit()
    session.close()

def saveVulnerability(vulnerability, session):
    alreadyExists = searchInTable(Vulnerability, vulnerability)
    if alreadyExists is not None:
        return
    vulnObject = Vulnerability(**vulnerability)

    session.add(vulnObject)
    session.commit()

def saveRelation(service, vulnerability, session):
    cve = vulnerability['cve_code']
    relation = getServiceVulnRelation(service, cve)
    if relation is None:
        return
    alreadyExists = searchInTable(ServiceVulnerability, relation)
    if alreadyExists is not None:
        return
    relationObject = ServiceVulnerability(**relation)

    session.add(relationObject)
    session.commit()

def getServiceVulnRelation(cpeCode, cveCode):
    service = searchInTable(Service, {"cpe_code": cpeCode})
    vuln = searchInTable(Vulnerability, {"cve_code": cveCode})

    if service is None:
        log(
            "cannot link nonexistent service {} with vuln {}".format(cpeCode, cveCode),
            printing=True
        )
        return

    if vuln is None:
        log(
            "cannot link service {} with nonexistent vuln {}".format(cpeCode, cveCode),
            printing=True
        )
        return

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
