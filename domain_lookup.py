import shodan
from random import randint
import time
import json 

def getDomainsList():
    with open("./data/domain_list",'r') as domains_file:
        domain_list = domains_file.read()
        domains_file.close()
        return domain_list.split(",")
    
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

def saveDomainInfo(domainName):
    relativePathToNewFile =f'./data/domain_raw_data/{domainName}'
    with open(relativePathToNewFile, "w") as domainInfoFile:
        domainInfoFile.write(getShodanInfoOf(domainName))
        domainInfoFile.close

def getAllRawData():
    allDomains = getDomainsList()
    for domain in allDomains:
        saveDomainInfo(domain)
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
    
def createIpList():
    allDomains = getDomainsList()
    with open('./data/ip_list', 'w') as ipList:
        for domain in allDomains:
            ipList.write(getDomainIp(domain))