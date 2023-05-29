import requests
import sys
import time
from common import (
    formatFilePath,
    formatDirPath,
)

if __name__ == "__main__":
    args = sys.argv[1:]
    try:
        if len(args):
            if len(args) < 3:
                raise Exception("""Se necesitan tres argumentos:
    1. la ruta al archivo con la lista de codigos CPE,
    2. La ruta al directorio donde se guardará la información correspondiente,
    3. La ruta al archivo con la llave de la API de Shodan.""")
            if len(args) == 3:
                cpeListFilePath = formatFilePath(args[1])
                vulnerabilitiesDataDirPath = formatDirPath(args[2])
    except:
        print('Hubo un error al buscar las vulnerabilidades')


def saveVulnerabilitiesFrom(cpeCode):
    print('Solicitando vulnerabilidades para {}'.format(cpeCode))

    request = queryCPE(cpeCode)

    res = request['vulnerabilities']

    totalResults = request['totalResults']
    print('Resultados totales:', totalResults)

    while len(res) <= totalResults:
        time.sleep(6)
        res += queryProduct(cpeCode, len(res))

    print('La solicitud de vulnerabilidades para {} ha terminado'.format(cpeCode))
    return res


def queryProduct(cpeCode, startIndex=0):
    request = requests.get(
        'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}&startIndex={}'.format(cpeCode, startIndex))
    request = request.json()
    return request["vulnerabilities"]


def queryCPE(cpeCode):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}'.format(cpeCode)
    request = requests.get(url)
    return request.json()
