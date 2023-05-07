import shodan
import random
import time
from json import loads

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

    return str(info)

def saveDomainInfo(domainName):
    relativePathToNewFile =f'./data/domain_raw_data/{domainName}'
    with open(relativePathToNewFile, "w") as domanInfoFile:
        domanInfoFile.write(getShodanInfoOf(domainName))
        domanInfoFile.close()

def getAllRawData():
    allDomains = getDomainsList()
    for domain in allDomains:
        saveDomainInfo(domain)
        time.sleep(random.uniform(5,10))
