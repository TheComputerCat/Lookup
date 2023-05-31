from common import (
    log
)
import json
from os import listdir
from os.path import isfile, join


def getJsonFromFile(path):
    try:
        f = open(path, 'r')
        json_ = json.load(f)
        f.close()
    except Exception as e:
        log(e, printing=True)
        return {}
    return json_

def hasData(json):
    return json is not None and 'data' in json

def filterJson(json):
    filteredJson = {}
    if hasData(json):
        filteredJson['domain'] = json['domain']
        filteredData = filterData(json['data'])
        for dataDomain in filteredData:
            filteredJson[dataDomain] = filteredData[dataDomain]
    return filteredJson

def formatRecord(data):
    newData = {key: data[key] for key in ['value', 'subdomain', 'ports', 'last_seen'] if key in data}
    newData['ports'] = newData['ports'] if 'ports' in newData else []
    return newData

def formatARecord(data):
    return formatRecord(data)

def formatMXRecord(data):
    return removeDictionaryKey(formatRecord(data), 'ports')

def removeDictionaryKey(dic, key):
    newDict = dict(dic)
    del newDict[key]
    return newDict

def removeSubdomainKey(dict):
    return removeDictionaryKey(dict, 'subdomain')

def isMainDomain(data):
    return data['subdomain'] == ''

def isARecord(data):
    return data['type'] == 'A'

def isMXRecord(data):
    return data['type'] == 'MX'

def isTXTRecord(data):
    return data['type'] == 'TXT'

def A():
    return formatARecord, isARecord

def MX():
    return formatMXRecord, isMXRecord

def TXT():
    return formatMXRecord, isTXTRecord

def getRecords(register, data):
    formatter, selector = register()
    recordData = list(map(formatter ,list(filter(selector, data))))

    main = list(map(removeSubdomainKey, list(filter(isMainDomain, recordData))))
    subdomains = list(filter(lambda x : not isMainDomain(x), recordData))
    return main, subdomains

REGISTERS = {
    'A': A,
    'MX': MX,
    'TXT': TXT
}

def filterData(json):
    filteredData = {'main': {}, 'subdomains': {}}

    for register in REGISTERS:
        main, subdomains = getRecords(REGISTERS[register], json)
        filteredData['main'][register] = main
        filteredData['subdomains'][register] = subdomains

    return filteredData

def getJoinedData(jsonList):
    joinedData = []
    for json in jsonList:
        if hasData(json):
            joinedData += json["data"]
    return joinedData

def getDomain(jsonList):
    return jsonList[0]["domain"]

def hasInfo(jsonList):
    return len(jsonList) > 0 and hasData(jsonList[0])

def filterFromJsonList(jsonList):
    if hasInfo(jsonList):
        joined = {
            "domain": getDomain(jsonList),
            "data": getJoinedData(jsonList)
        }

        return filterJson(joined)
    return {}
    
def extractDataFromFile(path):
    jsonList = getJsonFromFile(path)
    return filterFromJsonList(jsonList)

def extractDataFromFolder(path):
    filesInFolder = (join(path, f) for f in listdir(path) if isfile(join(path, f)))
    return list(map(extractDataFromFile, filesInFolder))


