import re

def parseNameServerLookupOutput(output:str):
    s1 = str(re.escape('name ='))
    s2 = str(re.escape('Authoritative'))
    return re.findall(s1+'(.*?)'+s2, output)[0]