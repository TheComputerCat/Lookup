# Get an IP address in string format and return
# the stdout of nmap with the default specification and scan order, on TCP and UDP.
import functools
import subprocess
import shodan

def getAddressList():
    with open("./data/ip_list", "r") as f:
        addresses = f.read()
    
    
    
    allAddresses = [address for address in addresses.split("\n") if address != ""]
    return list(dict.fromkeys(allAddresses))


def getNmapInfoOf(address: str, isIPv6: bool):
    if isIPv6:
        command = ["nmap", "-sT", "-sU", "-verbose", "-6", address]
    else:
        command = ["nmap", "-sT", "-sU", "-verbose", address]
    
    result = subprocess.run(command, capture_output=True, text=True)

    return result

def getShodanApi(keyFilePath:str):
    shodan_key = open(keyFilePath, 'r').read()
    return shodan.Shodan(shodan_key, 'r')

def getIPList(IPListFilePath):
    return open(IPListFilePath, 'r').read().splitlines()

def getDirectoryPathOf(filePath: str):
    return '/'.join(filePath.split("/")[0:-1])

def getIPFilePath(IP: str, IPListFilePath: str):
    path = getDirectoryPathOf(IPListFilePath)
    return path+'/ip_raw_data/'+IP

def saveShodanInfoOf(IPListFilePath: str, keyFilePath: str):
    api = getShodanApi(keyFilePath)
    IPList = getIPList(IPListFilePath)
    for IP in IPList:
        IPFile = open(getIPFilePath(IP, IPListFilePath))
        IPFile.write(api.host(IP))

    

