from common import log
from domain_lookup import getIteratorFromCSV
import csv
import re
import subprocess


def doNsLookupToListOfHosts(hostFilePath):
    hostList = getHostListFromPath(hostFilePath)
    for host in hostList:
        nslookupCommandWith(host)

def nslookupCommandWith(IP:str):
    return subprocess.run(['nslookup', IP], stdout=subprocess.PIPE)

def getHostListFromPath(path: str):
    CSVIterator, f = getIteratorFromCSV(path)

    try:
        domainColumnIndex = CSVIterator.__next__().index('host')
    except Exception as e:
        log(e)
        return []

    domainList = [row[domainColumnIndex] for row in CSVIterator]
    f.close()

    return domainList

def parseNameServerLookupOutput(output:str):
    s1 = str(re.escape('name ='))
    s2 = str(re.escape('Authoritative'))
    return re.findall(s1+'(.*?)'+s2, output)[0]
