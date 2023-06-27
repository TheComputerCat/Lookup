import sys
import subprocess

from src.common.common import (
    formatDirPath,
    formatFilePath,
)

import src.lookup.domain_lookup as domain_lookup
import src.lookup.host_lookup as host_lookup
import src.extract.domain_extract as domain_extract
import src.extract.host_extract as host_extract
import src.extract.host_extract_nmap as host_extract_nmap

import src.common.query_manager as query_manager

def getShodanDomainDataFolder(DATA_DIR):
    return DATA_DIR + 'data_domain_shodan_raw/'

def getAdressesListFilePath(DATA_DIR):
    return DATA_DIR + 'addresses.csv'

def getShodanHostDataFolder(DATA_DIR):
    return DATA_DIR + 'data_host_shodan/'
    
def getNmapHostDataFolder(DATA_DIR):
    return DATA_DIR + 'data_host_nmap/'

def domainLookup(DATA_DIR, DOMAIN_LIST_PATH, SHODAN_API_KEY):
    domain_lookup.saveShodanInfoFromDomainFile(DOMAIN_LIST_PATH, getShodanDomainDataFolder(DATA_DIR), SHODAN_API_KEY)
    domain_lookup.saveIpList(getAdressesListFilePath(DATA_DIR), getShodanDomainDataFolder(DATA_DIR))

def hostLookup(DATA_DIR, SHODAN_API_KEY):
    host_lookup.saveShodanInfoOf(getAdressesListFilePath(DATA_DIR), getShodanHostDataFolder(DATA_DIR), SHODAN_API_KEY)
    subprocess.run(['sudo', 'python3', '-m', 'src.lookup.host_lookup', 'nmap', getAdressesListFilePath(DATA_DIR), getNmapHostDataFolder(DATA_DIR)])

def domainExtract(DATA_DIR):
    domain_extract.insertDataFromFolder(getShodanDomainDataFolder(DATA_DIR))

def hostExtract(DATA_DIR):
    host_extract.setAddressDataDirPath(getShodanHostDataFolder(DATA_DIR))
    host_extract.completeServiceTable()
    host_extract.completeHostTable()
    host_extract.completeHostServiceTable()

    host_extract_nmap.completeTablesWithFilesFromPath(getNmapHostDataFolder(DATA_DIR))

def orchestrator(DATA_DIR, DOMAIN_LIST_PATH, SHODAN_API_KEY, DB_CONFIG_FILE_PATH):
    domainLookup(DATA_DIR, DOMAIN_LIST_PATH, SHODAN_API_KEY)

    hostLookup(DATA_DIR, SHODAN_API_KEY)

    query_manager.setConfigFile(DB_CONFIG_FILE_PATH)
    query_manager.createTables()

    domainExtract(DATA_DIR)

    hostExtract(DATA_DIR)

def getArguments():
    args = sys.argv[1:]

    if len(args) < 4:
        raise Exception("""Se necesitan cuatro argumentos:
        1. La ruta donde se guardaran los datos recolectados,
        2. La ruta al archivo con la lista de dominios,
        3. La ruta al archivo con la llave de la API de Shodan,
        4. La ruta a el archivo de credenciales de la base de datos""")

    DATA_DIR=formatDirPath(args[0])
    DOMAIN_LIST_PATH=formatFilePath(args[1])
    SHODAN_API_KEY=formatFilePath(args[2])
    DB_CONFIG_FILE_PATH=formatFilePath(args[3])

    return DATA_DIR, DOMAIN_LIST_PATH, SHODAN_API_KEY, DB_CONFIG_FILE_PATH

if __name__ == "__main__":
    orchestrator(*getArguments())