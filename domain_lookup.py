from common import (
    log,
    getStringFromFile,
    writeStringToFile,
)
import csv
import json
from random import randint
import shodan
import time


def getIteratorFromCSV(path: str, delimiter: str=","):
    try:
        f = open(path, "r", newline="")
        CSVRowsIterator = csv.reader(f, delimiter=delimiter)
    except Exception as e:
        log(e)
        return iter(()), None
    return CSVRowsIterator, f

def getDomainListFromPath(path: str):
    CSVIterator, f = getIteratorFromCSV(path)

    try:
        domainColumnIndex = CSVIterator.__next__().index("domain")
    except Exception as e:
        log(e)
        return []
    
    domainList = [row[domainColumnIndex] for row in CSVIterator]
    f.close()
    
    return domainList
    
def getShodanInfoOf(domain: str, APIkeyFilePath: str):
    key = getStringFromFile(APIkeyFilePath)

    api = shodan.Shodan(key)
    areMorePages = True
    info = []
    pageNumber = 1
    while areMorePages:
        newPage = api.dns.domain_info(domain=domain, history=False, type=None, page=pageNumber)
        info.append(newPage)
        areMorePages = newPage['more']
        pageNumber+=1

    return json.dumps(info)

def saveDomainInfo(domainName: str, domainInfoDirPath: str, APIkeyFilePath: str):
    relativePathToNewFile = f'{domainInfoDirPath}{domainName}'
    shodanInfo = getShodanInfoOf(domainName, APIkeyFilePath)
    writeStringToFile(relativePathToNewFile, shodanInfo, overwrite=True)

def saveShodanInfoFromDomainFile(domainListFilePath: str, domainDataDirPath: str, APIkeyFilePath: str):
    allDomains = getDomainListFromPath(domainListFilePath)
    for domain in allDomains:
        saveDomainInfo(domain, domainDataDirPath, APIkeyFilePath)

def getIPAddressesFromDict(JSONdict: dict):
    return [item['value'] for item in JSONdict if item['type'] in ['A', 'AAAA']]

def getIPAddressesFromShodanInfo(domainName: str, domainDataDirPath: str):
    relativePathToNewFile = f'{domainDataDirPath}{domainName}'
    jsonString = getStringFromFile(relativePathToNewFile)
    domainInfo = json.loads(jsonString)
    
    domainIPAddresses = []
    for page in domainInfo:
        domainIPAddresses += getIPAddressesFromDict(page['data'])

    return '\n'.join(domainIPAddresses) + '\n'
    
def saveIpList(domainListPath: str, IPListFilePath: str):
    allDomains = getDomainListFromPath(domainListPath)

    allDomainsIPAddresses = []
    for domain in allDomains:
        allDomainsIPAddresses.append(getIPAddressesFromShodanInfo(domain))

    result = '\n'.join(allDomainsIPAddresses) + '\n'
    writeStringToFile(IPListFilePath, result, overwrite=True)
