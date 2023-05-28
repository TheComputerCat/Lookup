import multiprocessing as mp
import random
import subprocess
import shodan
import time
import traceback
import sys
import os
from common import (
    log,
    asHexString, 
    formatDirPath,
    formatFilePath,
    getStringFromFile,
    getTimeString,
    writeStringToFile,
)

def getAddressListFromFile(path):
    addresses = getStringFromFile(path)
    
    allAddresses = [address for address in addresses.split("\n") if address != ""]
    return list(dict.fromkeys(allAddresses))


def getNmapCommands(address: str, addressDataDirPath: str):
    TCPCommand = ["nmap", "-sTV", "-top-ports", "2000", "--version-light", "-vv", "-oX", 
                  f"{addressDataDirPath}{asHexString(address)}-tcp{getTimeString()}", address]
    UDPCommand = ["nmap", "-sUV", "-top-ports", "200" , "--version-light", "-vv", "-oX",
                  f"{addressDataDirPath}{asHexString(address)}-udp{getTimeString()}", address]
    
    return TCPCommand, UDPCommand

def getNmapInfoOf(address: str, addressDataDirPath: str):
    TCPCommand, UDPCommand = getNmapCommands(address, addressDataDirPath)
    
    TCPResult = subprocess.run(TCPCommand, capture_output=True, text=True)
    yield {
        "stdout": TCPResult.stdout,
        "stderr": TCPResult.stderr,
    }

    UDPResult = subprocess.run(UDPCommand, capture_output=True, text=True)
    yield {
        "stdout": UDPResult.stdout,
        "stderr": UDPResult.stderr,
    }

def doNmapAndSaveStd(address: str, addressDataDirPath: str):
    NmapResultGenerator = getNmapInfoOf(address, addressDataDirPath)
    for result, label in zip(NmapResultGenerator, ['tcp-std', 'udp-std']):
        writeStringToFile(f'{addressDataDirPath}{asHexString(address)}-{label}{getTimeString()}', str(result), overwrite=True)

def saveNmapInfoFromAddressFile(addressListFilePath, addressDataDir):
    os.makedirs(addressDataDir, exist_ok=True)
    IPList = getAddressListFromFile(addressListFilePath)
    pool = mp.Pool(len(IPList))

    for address in IPList:
        try:
            pool.apply_async(doNmapAndSaveStd, args=(address, addressDataDir))
        except Exception as e:
            log(e, printing=True)
            continue
    
    pool.close()
    pool.join()

def getShodanApi(APIkeyFilePath: str):
    shodan_key = getStringFromFile(APIkeyFilePath)
    api = shodan.Shodan(shodan_key)
    return api

def getIPAddressesList(IPAddressesListFilePath):
    ipAddressesListFile = getStringFromFile(IPAddressesListFilePath)
    ipAddressesList = ipAddressesListFile.splitlines()
    return ipAddressesList

def getDirectoryPathOf(filePath: str):
    return '/'.join(filePath.split("/")[0:-1])

def getIPAddressFilePath(IP: str, addressDataDirPath: str):
    return f'{addressDataDirPath}{asHexString(IP)}{getTimeString()}'

def saveShodanInfoOf(IPAddressListFilePath: str, addressDataDirPath: str, keyFilePath: str):
    api = getShodanApi(keyFilePath)
    IPAddressesList = getAddressListFromFile(IPAddressListFilePath)
    for IPAddress in IPAddressesList:
        try:
            result = str(api.host(IPAddress))
        except Exception as e:
            log(e, printing=True)
            result = str(e)
        
        writeStringToFile(
            getIPAddressFilePath(IPAddress, addressDataDirPath),
            result,
            overwrite=True
        )
        time.sleep(random.uniform(5, 10))

if __name__ == "__main__":
    args = sys.argv[1:]
    try:
        if len(args) == 0:
            raise Exception("Se necesita escoger una opción entre 'shodan' y 'nmap'.")

        if args[0] == "shodan":
            if len(args) < 4:
                raise Exception("""Se necesitan tres argumentos más:
    1. la ruta al archivo con la lista de direcciones IP,
    2. La ruta al directorio donde se guardará la información de los hosts correspondientes,
    3. La ruta al archivo con la llave de la API de Shodan.""")
            addressListFilePath = formatFilePath(args[1])
            addressDataDirPath = formatDirPath(args[2])
            shodanAPIKeyFilePath = formatFilePath(args[3])

            saveShodanInfoOf(addressListFilePath, addressDataDirPath, shodanAPIKeyFilePath)
        elif args[0] == "nmap":
            if len(args) < 3:
                raise Exception("""Se necesitan tres argumentos más:
    1. la ruta al archivo con la lista de direcciones IP,
    2. La ruta al directorio donde se guardará la información de los hosts correspondientes.""")
            addressListFilePath = formatFilePath(args[1])
            addressDataDirPath = formatDirPath(args[2])

            saveNmapInfoFromAddressFile(addressListFilePath, addressDataDirPath)
    except Exception as e:
        print(traceback.format_exc())
