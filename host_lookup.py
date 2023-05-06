# Get an IP address in string format and return
# the stdout of nmap with the default specification and scan order, on TCP and UDP.

import subprocess

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
