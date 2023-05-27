from common import (
    log
)
import json
import os
import functools


def getJsonFromFile(filePath):
    try:
        f = open(filePath, 'r')
        jsonDic = json.load(f)
        f.close()
    except Exception as e:
        log(e, printing=True)
        return {}
    return jsonDic

def hasData(jsonDic):
    return jsonDic is not None and 'data' in jsonDic

def filterJson(jsonDic):
    filteredJson = {}
    if hasData(jsonDic):
        filteredJson['domain'] = jsonDic['domain']
        filteredData = filterData(jsonDic['data'])
        for dataDomain in filteredData:
            filteredJson[dataDomain] = filteredData[dataDomain]
    return filteredJson

def formatRegister(data):
    newData = {key: data[key] for key in ['value', 'subdomain', 'ports', 'last_seen'] if key in data}
    newData['ports'] = newData['ports'] if 'ports' in newData else []
    return newData

def formatARegisters(data):
    return formatRegister(data)

def formatMXRegisters(data):
    return removeKeyDictionary(formatRegister(data), 'ports')

def removeKeyDictionary(dic, key):
    newDict = dict(dic)
    del newDict[key]
    return newDict

def removeSubdomainKey(dict):
    return removeKeyDictionary(dict, 'subdomain')

def isMainDomain(data):
    return data['subdomain'] == ''

def isARegister(data):
    return data['type'] == 'A'

def isMXRegister(data):
    return data['type'] == 'MX'

def isTXTRegister(data):
    return data['type'] == 'TXT'


def filterData(jsonData):
    filteredData = {'main': {}, 'subdomains': {}}

    A = list(map(formatARegisters ,list(filter(isARegister, jsonData))))
    MX = list(map(formatMXRegisters ,list(filter(isMXRegister, jsonData))))
    TXT = list(map(formatMXRegisters ,list(filter(isTXTRegister, jsonData))))

    filteredData['main']['A'] = list(map(removeSubdomainKey ,list(filter(isMainDomain, A))))
    filteredData['main']['MX'] = list(map(removeSubdomainKey ,list(filter(isMainDomain, MX))))
    filteredData['main']['TXT'] = list(map(removeSubdomainKey ,list(filter(isMainDomain, TXT))))

    filteredData['subdomains']['A'] = list(filter(lambda x : not isMainDomain(x), A))
    filteredData['subdomains']['MX'] = list(filter(lambda x : not isMainDomain(x), MX))
    filteredData['subdomains']['TXT'] = list(filter(lambda x : not isMainDomain(x), TXT))

    return filteredData


