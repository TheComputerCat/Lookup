from common import (
    log,
    asHexString,
    getFilePathsInDirectory,
    getStringFromFile,
    writeStringToFile,
    formatFilePath,
    formatDirPath,
    getTimeString,
)
import csv
import json
import os
import shodan
import sys
import traceback

def getIteratorFromCSV(path: str, delimiter: str=","):
    try:
        f = open(path, "r", newline="")
        CSVRowsIterator = csv.reader(f, delimiter=delimiter)
    except Exception as e:
        log(e, printing=True)
        return iter(()), None
    return CSVRowsIterator, f

def getDomainListFromPath(path: str):
    CSVIterator, f = getIteratorFromCSV(path)

    try:
        domainColumnIndex = CSVIterator.__next__().index("domain")
    except Exception as e:
        log(e, printing=True)
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
    relativePathToNewFile = f'{domainInfoDirPath}{asHexString(domainName)}{getTimeString()}'
    shodanInfo = getShodanInfoOf(domainName, APIkeyFilePath)
    writeStringToFile(relativePathToNewFile, shodanInfo, overwrite=True)

def saveShodanInfoFromDomainFile(domainListFilePath: str, domainDataDirPath: str, APIkeyFilePath: str):
    allDomains = getDomainListFromPath(domainListFilePath)
    for domain in allDomains:
        saveDomainInfo(domain, domainDataDirPath, APIkeyFilePath)

def getIPAddressesFromDict(JSONdict: dict):
    return [item['value'] for item in JSONdict if item['type'] == 'A' and item['subdomain'] == '']

def getIPAddressesFromShodanInfo(domainInfoFilePath):
    jsonString = getStringFromFile(domainInfoFilePath)
    domainInfo = json.loads(jsonString)
    
    domainIPAddresses = sum(map(getIPAddressesFromDict, [page['data'] for page in domainInfo]), [])

    return '\n'.join(domainIPAddresses) + '\n'
    
def saveIpList(IPListFilePath: str, domainDataDirPath: str):
    domainInfoFilePaths = getFilePathsInDirectory(domainDataDirPath)

    allDomainsIPAddresses = map(getIPAddressesFromShodanInfo, domainInfoFilePaths)

    result = '\n'.join(allDomainsIPAddresses) + '\n'
    writeStringToFile(IPListFilePath, result, overwrite=True)

if __name__ == '__main__':
    args = sys.argv[1:]
    try:
        if len(args) == 0:
            raise Exception("Se necesita escoger una opción entre 'lookup' y 'get_addresses'.")

        if   args[0] == 'lookup':
            if len(args) < 4:
                raise Exception("""Se necesitan tres argumentos más:
    1. la ruta al archivo con la lista de dominios,
    2. La ruta al directorio donde se guardará la información de los dominios,
    3. La ruta al archivo con la llave de la API de Shodan.""")
            domainListFilePath = formatFilePath(args[1])
            domainDataDirPath = formatDirPath(args[2])
            shodanAPIKeyFilePath = formatFilePath(args[3])
            
            saveShodanInfoFromDomainFile(domainListFilePath, domainDataDirPath, shodanAPIKeyFilePath)
        elif args[0] == 'get_addresses':
            if len(args) < 3:
                raise Exception("""Se necesitan dos argumentos más:
    1. la ruta al archivo donde se guardarán las direcciones,
    2. La ruta al directorio donde está la información de los dominios.""")
            addressListFilePath = formatFilePath(args[1])
            domainDataDirPath = formatDirPath(args[2])

            saveIpList(addressListFilePath, domainDataDirPath)
    except Exception as e:
        print(traceback.format_exc())
