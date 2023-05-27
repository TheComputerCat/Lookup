from common import (
    tryTo,
)

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

