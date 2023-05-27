from common import (
    tryTo,
)

import DB_API

def getAttrFromDict(dict, key):
    return tryTo(lambda: dict[key], None)

def getListFromDict(dict, key):
    return tryTo(lambda: dict[key], [])

def trimServiceInfo(dict):
    return {
        "service": getAttrFromDict(dict, "product"),
        "version": getAttrFromDict(dict, "version"),
        "cpe": getListFromDict(dict, "cpe"),
        "cpe23": getListFromDict(dict, "cpe23"),
        "timestamp": getAttrFromDict(dict, "timestamp"),
        "port": getAttrFromDict(dict, "port"),
    }

def getServicesFromDict(dict):
    data = getListFromDict(dict, 'data')
    return list(
        map(
            trimServiceInfo,
            filter(lambda aDict: "product" in aDict, data)
        )
    )

def getHostInfoFromDict(dict):
    address = getAttrFromDict(dict, "ip_str")
    if address is None:
        return {}
    
    return {
        "ip": address,
        "hostnames": getListFromDict(dict, 'hostnames'),
        "ports": getListFromDict(dict, 'ports'),
        "country": getAttrFromDict(dict, 'country_code'),
        "services": getServicesFromDict(dict),
    }

def getServiceRowFromServiceDict(serviceDict):
    return {
        "name": getAttrFromDict(serviceDict, "service"),
        "version": getAttrFromDict(serviceDict, "version"),
    }

def insertServiceRowsFromTrimmedDict(trimmedDict):
    SERVICES = "SERVICES"

    rowsToInsert = filter(
        lambda row: not DB_API.isRowInTable(SERVICES, row),
        map(getServiceRowFromServiceDict, trimmedDict["services"])
    )

    for row in rowsToInsert:
        DB_API.insert_in(SERVICES, row)

def getHostRowID(address):
    HOSTS = "HOSTS"

    row = {"address": address}
    if not DB_API.isRowInTable(HOSTS, row):
        DB_API.insert_in(HOSTS, row)
    
    query = DB_API.searchForSingleRowQuery(HOSTS, row, cols=["id"])

    response = DB_API._execute(query, return_results=True)

    return tryTo(lambda: response[0][0], None)

def getServiceRowID(serviceDict):
    SERVICES = "SERVICES"

    row = getServiceRowFromServiceDict(serviceDict)
    if not DB_API.isRowInTable(SERVICES, row):
        DB_API.insert_in(SERVICES, row)
    
    query = DB_API.searchForSingleRowQuery(SERVICES, row, cols=["id"])

    response = DB_API._execute(query, return_results=True)

    return tryTo(lambda: response[0][0], None)

def getHostServiceRowFromAddressID(addressRowID):
    return lambda serviceDict: {
        "host": addressRowID,
        "service": getServiceRowID(serviceDict),
        "timestamp": serviceDict["timestamp"],
        "port": serviceDict["port"],
    }

def insertHostServiceRowsFromTrimmedDict(trimmedDict):
    HOST_SERVICES = "HOST_SERVICES"

    addressRowID = getHostRowID(trimmedDict["address"])
    addressFixer = getHostServiceRowFromAddressID(addressRowID)

    rowsToInsert = filter(
        lambda row: not DB_API.isRowInTable(HOST_SERVICES, row),
        map(addressFixer, trimmedDict["services"])
    )

    for row in rowsToInsert:
        DB_API.insert_in(HOST_SERVICES, row)
