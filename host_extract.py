from common import (
    tryTo,
)

import DB_API

def getAttrFromDict(dict, key):
    return tryTo(lambda: dict[key], None)

def getListFromDict(dict, key):
    return tryTo(lambda: dict[key], [])

def getCountryCodeFromDict(dict):
    return getAttrFromDict(dict, 'country_code')

def getHostNamesFromDict(dict):
    return getListFromDict(dict, 'hostnames')

def getPortsFromDict(dict):
    return getListFromDict(dict, 'ports')

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
        "hostnames": getHostNamesFromDict(dict),
        "ports": getPortsFromDict(dict),
        "country": getCountryCodeFromDict(dict),
        "services": getServicesFromDict(dict),
    }

def getServiceRowFromServiceDict(serviceDict):
    return {
        "name": getAttrFromDict(serviceDict, "service"),
        "version": getAttrFromDict(serviceDict, "version"),
    }

def getHostRowID(address):
    row = {"address": address}
    if not DB_API.isRowInTable("HOSTS", row):
        DB_API.insert_in("HOSTS", row)
    
    query = DB_API.searchForSingleRowQuery("HOSTS", row)

    response = DB_API._execute(query, return_results=True)

    return tryTo(lambda: response[0], None)


def insertServiceRowsFromTrimmedDict(trimmedDict):
    SERVICES = "SERVICES"

    rowsToInsert = filter(
        lambda row: not DB_API.isRowInTable(SERVICES, row),
        map(getServiceRowFromServiceDict, trimmedDict["services"])
    )

    for row in rowsToInsert:
        DB_API.insert_in(SERVICES, row)
