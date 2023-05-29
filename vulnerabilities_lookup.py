import requests
import sys
import time
from common import (
    formatFilePath,
    formatDirPath,
    getTimeString,
    writeStringToFile,
    getStringFromFile,
    log,
)


def queryProduct(cpeCode, startIndex=0):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}&startIndex={}'.format(cpeCode, startIndex)
    request = requests.get(url)
    return request.json()


def getVulnerabilitiesOf(cpeCode):
    print('Solicitando vulnerabilidades para {}'.format(cpeCode))

    request = queryProduct(cpeCode)

    vulnerabilities = request['vulnerabilities']
    numberOfVulnerabilities = request['totalResults']

    while len(vulnerabilities) < numberOfVulnerabilities:
        time.sleep(6)
        moreVulnerabilities = queryProduct(cpeCode, len(vulnerabilities))["vulnerabilities"]
        vulnerabilities += moreVulnerabilities

    print('La solicitud de vulnerabilidades para {} ha terminado'.format(cpeCode))
    return vulnerabilities

def saveVulnerabilitiesOfProducts(cpeCodesFilePath, vulnerabilitiesDirectoryPath):
    file = open(cpeCodesFilePath)
    file.readline()
    while True:
        code = file.readline().strip()
        if not code:
            break
        try:
            vulnerabilities = getVulnerabilitiesOf(code)
            writeStringToFile(f'{vulnerabilitiesDirectoryPath}_{code}_{getTimeString()}', vulnerabilities, True)
        except Exception as e:
            log(e)
    file.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args):
        if len(args) != 3:
            raise Exception("""Se necesitan tres argumentos:
1. la ruta al archivo con la lista de codigos CPE,
2. La ruta al directorio donde se guardará la información correspondiente,
3. La ruta al archivo con la llave de la API de Shodan.""")
        if len(args) == 3:
            try:
                cpeCodesFilePath = formatFilePath(args[1])
                vulnerabilitiesDirectoryPath = formatDirPath(args[2])
                saveVulnerabilitiesOfProducts(cpeCodesFilePath, vulnerabilitiesDirectoryPath)
            except:
                print('Hubo un error al buscar las vulnerabilidades')
