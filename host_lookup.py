import random
import subprocess
import shodan
import time
from common import (
    log, 
    getStringFromFile,
    writeStringToFile,
)

def getAddressListFromFile(path):
    addresses = getStringFromFile(path)
    
    allAddresses = [address for address in addresses.split("\n") if address != ""]
    return list(dict.fromkeys(allAddresses))


def getNmapCommands(address: str, isIPv6: bool):
    TCPCommand = ["nmap", "-sTV", "-top-ports", "5000", "--version-light", "-vv", "-oX"]
    UDPCommand = ["nmap", "-sUV", "-top-ports", "200" , "--version-light", "-vv", "-oX"]
    if isIPv6:
        TCPCommand += ["-6", address]
        UDPCommand += ["-6", address]
    else:
        TCPCommand += [address]
        UDPCommand += [address]
    
    return TCPCommand, UDPCommand

def getNmapInfoOf(address: str, isIPv6: bool):
    TCPCommand, UDPCommand = getNmapCommands(address, isIPv6)
    
    TCPResult = subprocess.run(TCPCommand, capture_output=True, text=True)
    UDPResult = subprocess.run(UDPCommand, capture_output=True, text=True)

    return {
        "tcp": {
            "stdout": TCPResult.stdout,
            "stderr": TCPResult.stderr,
        },
        "udp": {
            "stdout": UDPResult.stdout,
            "stderr": UDPResult.stderr,
        },
    }

def saveNmapInfoFromAddressFile(addressListFilePath, addressDataDir):
    IPList = getAddressListFromFile(addressListFilePath)
    for address in IPList:
        try:
            result = str(getNmapInfoOf(address, ":" in address))
        except Exception as e:
            log(e)
            continue
        finally:
            random.uniform(5,10)
        
        writeStringToFile(f'{addressDataDir}{address}', result, overwrite=True)

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
    IPAddressesList = getIPAddressesList(IPAddressListFilePath)
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
            saveNmapInfoFromAddressFile('./data/ip_list')
    except:
        print("Elige una opción entre 'nmap' y 'shodan'.")
        print("Ejemplo: python host_lookup.py shodan")
        print("Para usar la opción 'nmap' se requieren privilegios de superusuario.")
