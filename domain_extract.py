from common import (
    log
)
import json


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

def A():
    return formatARegisters, isARegister

def MX():
    return formatMXRegisters, isMXRegister

def TXT():
    return formatMXRegisters, isTXTRegister

def getRegister(register, data):
    formatter, selector = register()
    registerData = list(map(formatter ,list(filter(selector, data))))

    main = list(map(removeSubdomainKey, list(filter(isMainDomain, registerData))))
    subdomains = list(filter(lambda x : not isMainDomain(x), registerData))
    return main, subdomains

REGISTERS = {
    'A': A,
    'MX': MX,
    'TXT': TXT
}
def filterData(jsonData):
    filteredData = {'main': {}, 'subdomains': {}}

    for register in REGISTERS:
        main, subdomains = getRegister(REGISTERS[register], jsonData)
        filteredData['main'][register] = main
        filteredData['subdomains'][register] = subdomains

    return filteredData


