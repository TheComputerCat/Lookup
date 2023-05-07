import subprocess
import shodan

def getAddressList():
    with open("./data/ip_list", "r") as f:
        addresses = f.read()
    
    allAddresses = [address for address in addresses.split("\n") if address != ""]
    return list(dict.fromkeys(allAddresses))


def getNmapCommand(address: str, isIPv6: bool, tcp=True):
    TCPCommand = ["nmap", "-sSV", "-top-ports", "5000", "--version-light", "-vv", "-oX"]
    UDPCommand = ["nmap", "-sUV", "-top-ports", "200", "--version-light", "-vv", "-oX"]
    if isIPv6:
        TCPCommand += ["-6", address]
        UDPCommand += ["-6", address]
    else:
        TCPCommand += [address]
        UDPCommand += [address]
    
    if tcp:
        return TCPCommand
    return UDPCommand

def getNmapInfoOf(address: str, isIPv6: bool):
    TCPCommand = getNmapCommand(address, isIPv6, tcp=True)
    UDPCommand = getNmapCommand(address, isIPv6, tcp=False)
    
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

def getShodanApi(keyFilePath:str):
    shodan_key = open(keyFilePath, 'r')
    api = shodan.Shodan(shodan_key.read())
    shodan_key.close()
    return api

def getIPList(IPListFilePath):
    ipListFile = open(IPListFilePath, 'r')
    ipList = ipListFile.read().splitlines()
    ipListFile.close()
    return ipList

def getDirectoryPathOf(filePath: str):
    return '/'.join(filePath.split("/")[0:-1])

def getIPFilePath(IP: str, IPListFilePath: str):
    path = getDirectoryPathOf(IPListFilePath)
    return path+'/ip_raw_data/'+IP

def saveShodanInfoOf(IPListFilePath: str, keyFilePath: str):
    api = getShodanApi(keyFilePath)
    IPList = getIPList(IPListFilePath)
    for IP in IPList:
        IPFile = open(getIPFilePath(IP, IPListFilePath), 'w')
        try:
            result = str(api.host(IP))
        except Exception as e:
            result = str(e)
        IPFile.write(result)
