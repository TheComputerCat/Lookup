THIRD_VERSION = "3.1"

def trimVulnerabilityInfo(cve, version):
    cveScoreFromVersion = getAttribute(cve['metrics'], version)
    if cveScoreFromVersion == None:
        return
    cveScoring = cveScoreFromVersion[0]['cvssData']
    return {
        "cve": getCveId(cve),
        "baseScore": getBaseScore(cveScoring),
        "vector": getAccessVectorScore(cveScoring),
        "complexity": getAccessComplexityScore(cveScoring),
        "authentication": getAuthenticationRequirement(cveScoring),
        "confidentialityImpact": getConfidentialityImpact(cveScoring),
        "integrityImpact": getIntegrityImpact(cveScoring),
        "availabilityImpact": getAvailabilityImpact(cveScoring),
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
