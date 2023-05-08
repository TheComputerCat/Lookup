import random
import subprocess
import shodan
import time

def getAddressList():
    with open("./data/ip_list", "r") as f:
        addresses = f.read()
    
    allAddresses = [address for address in addresses.split("\n") if address != ""]
    return list(dict.fromkeys(allAddresses))


def getNmapCommands(address: str, isIPv6: bool):
    TCPCommand = ["nmap", "-sSV", "-top-ports", "5000", "--version-light", "-vv", "-oX"]
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

def saveNmapInfo():
    IPList = getAddressList()
    for address in IPList:
        IPFile = open("./data/raw_nmap_data/{}".format(address), "w")
        try:
            result = str(getNmapInfoOf(address, ":" in address))
        except Exception as e:
            result = str(e)

        IPFile.write(result)
        IPFile.close()
        random.uniform(5,10)

def getShodanApi(keyFilePath:str):
    shodan_key = open(keyFilePath, 'r')
    api = shodan.Shodan(shodan_key.read())
    shodan_key.close()
    return api

def getIPAddressesList(IPAddressesListFilePath):
    ipAddressesListFile = open(IPAddressesListFilePath, 'r')
    ipAddressesList = ipAddressesListFile.read().splitlines()
    ipAddressesListFile.close()
    return ipAddressesList

def getDirectoryPathOf(filePath: str):
    return '/'.join(filePath.split("/")[0:-1])

def getIPAddressFilePath(IP: str, IPAddressesListFilePath: str):
    path = getDirectoryPathOf(IPAddressesListFilePath)
    return path+'/ip_raw_data/'+IP

def saveShodanInfoOf(IPAddressListFilePath: str, keyFilePath: str):
    api = getShodanApi(keyFilePath)
    IPAddressesList = getIPAddressesList(IPAddressListFilePath)
    for IPAddress in IPAddressesList:
        IPAddressFile = open(getIPAddressFilePath(IPAddress, IPAddressListFilePath), 'w')
        try:
            result = str(api.host(IPAddress))
        except Exception as e:
            result = str(e)
        IPAddressFile.write(result)
        IPAddressFile.close()
        time.sleep(random.uniform(5, 10))

if __name__ == "__main__":
    import sys
    
    try:
        args = sys.argv[1:]

        if args[0] == "shodan":
            saveShodanInfoOf("./data/ip_list", "./shodan_api_key")
        elif args[0] == "nmap":
            saveNmapInfo()
    except:
        print("Elige una opción entre 'nmap' y 'shodan'.")
        print("Ejemplo: python host_lookup.py shodan")
        print("Para usar la opción 'nmap' se requieren privilegios de superusuario.")
