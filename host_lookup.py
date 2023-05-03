# Get an IP address in string format and return
# the stdout of nmap with the default specification and scan order, on TCP and UDP.

import subprocess

def getNmapInfoOf(address: str, isIPv6: bool):
    command = ["nmap", "-sT", "-sU", "-verbose", address]
    result = subprocess.run(command, capture_output=True, text=True)

    return result
