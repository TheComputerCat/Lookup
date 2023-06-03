from common import (
    log
)
from datetime import datetime
import json as JSON
from os import listdir
from os.path import isfile, join
import model as model


from datetime import datetime
import json as JSON
from os import listdir
from os.path import isfile, join
import model as model


def getJsonFromFile(path):
    try:
        f = open(path, 'r')
        json_ = JSON.load(f)
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

RECORDS = {
    'A': A,
    'MX': MX,
    'TXT': TXT
}

def filterData(json):
    filteredData = {'main': {}, 'subdomains': {}}

    for record in RECORDS:
        main, subdomains = getRecords(RECORDS[record], json)
        filteredData['main'][record] = main
        filteredData['subdomains'][record] = subdomains

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

#############################################################################################

def ARecordObject(AJson):
    return model.ARecord(ip_address=AJson['value'], timestamp=getTimeFromString(AJson['last_seen']))

def MXRecordObject(MXJson):
    return model.MXRecord(domain=MXJson['value'], timestamp=getTimeFromString(MXJson['last_seen']))

def TXTRecordObject(TXTJson):
    return model.TXTRecord(content=TXTJson['value'], timestamp=getTimeFromString(TXTJson['last_seen']))

def getTimeFromString(strTime):
    return datetime.strptime(strTime[:19], '%Y-%m-%dT%H:%M:%S')

def recordsFromList(type, records):
    return list(map(type, records))

def subdomainObject(record, type):
    return {
        'subdomain': model.DomainInfo(domain=record['subdomain'], subdomain=True),
        'info': type(record),
    }

def recordsSubdomainFromList(type, records):
    return list(map(lambda record: subdomainObject(record, type), records))

RECORDS_OBJECTS = {
    'A': ARecordObject,
    'MX': MXRecordObject,
    'TXT': TXTRecordObject
}

def convertToOrmObjects(json):
    jsonWithObjects = {'main': {}, 'subdomains' : {}}
    jsonWithObjects['main_domain'] = model.MainDomain(name=json['domain'])
    jsonWithObjects['main_domain_info'] = model.DomainInfo(domain='', subdomain=False)

    for record in RECORDS_OBJECTS:
        jsonWithObjects['main'][record] = recordsFromList(RECORDS_OBJECTS[record], json['main'][record])
        jsonWithObjects['subdomains'][record] = recordsSubdomainFromList(RECORDS_OBJECTS[record], json['subdomains'][record])

    return jsonWithObjects

