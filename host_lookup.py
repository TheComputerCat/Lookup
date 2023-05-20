import random
import subprocess
import shodan
import time
import traceback
from common import (
    log,
    asHexString, 
    getStringFromFile,
    getTimeString,
    writeStringToFile,
)

def getAddressListFromFile(path):
    addresses = getStringFromFile(path)
    
    allAddresses = [address for address in addresses.split("\n") if address != ""]
    return list(dict.fromkeys(allAddresses))


def getNmapCommands(address: str):
    TCPCommand = ["nmap", "-sTV", "-top-ports", "5000", "--version-light", "-vv", "-oX", address]
    UDPCommand = ["nmap", "-sUV", "-top-ports", "200" , "--version-light", "-vv", "-oX", address]
    
    return TCPCommand, UDPCommand

def getNmapInfoOf(address: str):
    TCPCommand, UDPCommand = getNmapCommands(address)
    
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

def saveNmapInfoFromAddressFile(addressListFilePath, addressDataDir):
    IPList = getAddressListFromFile(addressListFilePath)
    for address in IPList:
        NmapResultGenerator = getNmapInfoOf(address)
        try:
            for result, label in zip(NmapResultGenerator, ['tcp', 'udp']):
                writeStringToFile(f'{addressDataDir}{asHexString(address)}-{label}{getTimeString()}', str(result), overwrite=True)
        except Exception as e:
            log(e)
            continue
        finally:
            time.sleep(random.uniform(5,10))

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
    return f'{addressDataDirPath}{IP}'

def saveShodanInfoOf(IPAddressListFilePath: str, addressDataDirPath: str, keyFilePath: str):
    api = getShodanApi(keyFilePath)
    IPAddressesList = getAddressListFromFile(IPAddressListFilePath)
    for IPAddress in IPAddressesList:
        try:
            result = str(api.host(IPAddress))
        except Exception as e:
            log(e)
            result = str(e)
        
        writeStringToFile(
            getIPAddressFilePath(IPAddress, addressDataDirPath),
            result,
            overwrite=True
        )
        time.sleep(random.uniform(5, 10))

if __name__ == "__main__":
    import sys
    
    try:
        args = sys.argv[1:]

        if args[0] == "shodan":
            saveShodanInfoOf("./data/ip_list", "./data/ip_raw_data/", "./shodan_api_key")
        elif args[0] == "nmap":
            saveNmapInfoFromAddressFile('./data/ip_list', './data/raw_nmap_data')
        else:
            print("Elige una opción entre 'nmap' y 'shodan'.")
            print("Ejemplo: python host_lookup.py shodan")
            print("Para usar la opción 'nmap' se requieren privilegios de superusuario.")
    except Exception as e:
        print(e)
        print(traceback.format_exc())
