from common import (
    tryTo,
)

from model import (
    CPECode,
    Host,
    HostService,
)

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
