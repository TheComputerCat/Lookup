def getAttribute(element, attribute):
    return element.get(attribute)

def getCveId(cve):
    return getAttribute(cve,'id')

def getBaseScore(cveScoring):
    return getAttribute(cveScoring, 'baseScore')

def getAccessVectorScore(cveScoring):
    return getAttribute(cveScoring, 'attackVector')

def getAccessComplexityScore(cveScoring):
    return getAttribute(cveScoring, 'attackComplexity')

def getAuthenticationRequirement(cveScoring):
    return getAttribute(cveScoring, 'privilegesRequired')

def getConfidentialityImpact(cveScoring):
    return getAttribute(cveScoring,'confidentialityImpact')

def getIntegrityImpact(cveScoring):
    return getAttribute(cveScoring,'integrityImpact')

def getAvailabilityImpact(cveScoring):
    return getAttribute(cveScoring, 'availabilityImpact')
