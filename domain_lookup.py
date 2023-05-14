import common
import csv
import json
from random import randint
import shodan
import time
import os


def getStringFromFile(path: str):
    try:
        f = open(path, "r")
        string = f.read()
        f.close()
    except Exception as e:
        common.log(e)
        return ""
    
    return string

def writeStringToFile(path: str, content: str, overwrite: bool=False):
    writeType = { False: "a", True: "w" }[overwrite]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        f = open(path, writeType)
        f.write(content)
        f.close()
        return True
    except Exception as e:
        common.log(e)
        return False

def getIteratorFromCSV(path: str, delimiter: str=","):
    try:
        f = open(path, "r", newline="")
        CSVRowsIterator = csv.reader(f, delimiter=delimiter)
    except Exception as e:
        common.log(e)
        return iter(()), None
    return CSVRowsIterator, f

def getDomainListFromPath(path: str):
    CSVIterator, f = getIteratorFromCSV(path)

    try:
        domainColumnIndex = CSVIterator.__next__().index("domain")
    except Exception as e:
        common.log(e)
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
    relativePathToNewFile = domainInfoDirPath+domainName
    writeStringToFile(relativePathToNewFile, getShodanInfoOf(domainName, APIkeyFilePath ), overwrite=True)

def saveAllDomainsInfo(domainListFilePath: str, domainDataDirPath: str, APIkeyFilePath: str):
    allDomains = getDomainListFromPath(domainListFilePath)
    for domain in allDomains:
        saveDomainInfo(domain, domainDataDirPath, APIkeyFilePath)
        time.sleep(randint(5,10))

def getDomainIp(domainName: str, domainDataDirPath: str):
    domainIp = []
    relativePathToNewFile = f'{domainDataDirPath}{domainName}'
    jsonString = getStringFromFile(relativePathToNewFile)
    domainInfo = json.loads(jsonString)
    for page in domainInfo:
        for dataObject in page['data']:
            if dataObject['type'] == 'A' or dataObject['type'] == 'AAAA':
                domainIp.append(dataObject['value'])
    return '{}\n'.format('\n'.join(domainIp))
    
def saveIpList(path: str, IPListFilePath: str):
    allDomains = getDomainListFromPath(path)
    allDomainsIp = []
    for domain in allDomains:
        allDomainsIp.append(getDomainIp(domain))
    writeStringToFile(IPListFilePath, '{}\n'.format('\n'.join(allDomainsIp)), overwrite=True)
