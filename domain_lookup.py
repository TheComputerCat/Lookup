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
        domainList = [row[domainColumnIndex] for row in CSVIterator]
        f.close()
        return domainList
    except Exception as e:
        common.log(e)
    
    return []
    
def getShodanInfoOf(domain: str):
    with open("shodan_api_key") as f:
        key = f.read()

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

def saveDomainInfo(domainName: str, domainInfoDirPath: str):
#     relativePathToNewFile = f'./data/domain_raw_data/{domainName}'
    relativePathToNewFile = domainInfoDirPath+domainName
    os.makedirs(os.path.dirname(relativePathToNewFile), exist_ok=True)
    with open(relativePathToNewFile, "w") as domainInfoFile:
        domainInfoFile.write(getShodanInfoOf(domainName))
        domainInfoFile.close()

def saveAllDomainsInfo():
    allDomains = getDomainListFromPath('./data/domain_list')
    for domain in allDomains:
        saveDomainInfo(domain, './data/domain_raw_data/')
        time.sleep(randint(5,10))

def getDomainIp(domainName):
    domainIp = []
    relativePathToNewFile =f'./data/domain_raw_data/{domainName}'
    with open(relativePathToNewFile, "r") as domainInfoFile:
        domainInfo = json.loads(domainInfoFile.read())
        domainInfoFile.close()
        for page in domainInfo:
            for dataObject in page['data']:
                if dataObject['type'] == 'A' or dataObject['type'] == 'AAAA':
                    domainIp.append(dataObject['value'])
        return ','.join(domainIp)
    
def saveIpList(path='./data/domain_raw_data'):
    allDomains = getDomainListFromPath(path)
    allDomainsIp = []
    for domain in allDomains:
        allDomainsIp.append(getDomainIp(domain))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open("./data/ip_list", 'w') as ipList:
            ipList.write(','.join(allDomainsIp))
            ipList.close()
