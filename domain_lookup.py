from common import (
    log,
    asHexString,
    getStringFromFile,
    writeStringToFile,
)
import csv
import json
import os
import shodan
import sys

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
    relativePathToNewFile = f'{domainInfoDirPath}{asHexString(domainName)}'
    shodanInfo = getShodanInfoOf(domainName, APIkeyFilePath)
    writeStringToFile(relativePathToNewFile, shodanInfo, overwrite=True)

def saveShodanInfoFromDomainFile(domainListFilePath: str, domainDataDirPath: str, APIkeyFilePath: str):
    allDomains = getDomainListFromPath(domainListFilePath)
    for domain in allDomains:
        saveDomainInfo(domain, domainDataDirPath, APIkeyFilePath)

def getIPAddressesFromDict(JSONdict: dict):
    return [item['value'] for item in JSONdict if item['type'] == 'A']

def getIPAddressesFromShodanInfo(domainInfoFilePath):
    jsonString = getStringFromFile(domainInfoFilePath)
    domainInfo = json.loads(jsonString)
    
    domainIPAddresses = sum(map(getIPAddressesFromDict, [page['data'] for page in domainInfo]), [])

    return '\n'.join(domainIPAddresses) + '\n'
    
def saveIpList(IPListFilePath: str, domainDataDirPath: str):
    domainInfoFilePaths = [
        domainDataDirPath+fileName for fileName in os.listdir(domainDataDirPath)
        if os.path.isfile(domainDataDirPath+fileName)
    ]

    allDomainsIPAddresses = sum(map(getIPAddressesFromShodanInfo, domainInfoFilePaths), [])

    result = '\n'.join(allDomainsIPAddresses) + '\n'
    writeStringToFile(IPListFilePath, result, overwrite=True)


if __name__ == '__main__':
    args = sys.argv[1:]

    if   args[0] == 'lookup':
        saveShodanInfoFromDomainFile('./data/domain_list', './data/domain_raw_data/', './shodan_api_key')
    elif args[0] == 'get_addresses':
        saveIpList('./data/ip_list', './data/domain_raw_data/')
