# Get an IP address in string format and return
# the stdout of nmap with the default specification and scan order, on TCP and UDP.

import subprocess

def getAddressList():
    with open("./data/ip_list", "r") as f:
        addresses = f.read()
    return list(set([address for address in addresses.split("\n") if address != ""]))


def getNmapInfoOf(address: str, isIPv6: bool):
    command = ["nmap", "-sT", "-sU", "-verbose", address]
    result = subprocess.run(command, capture_output=True, text=True)

    return result
