from common import (
    getDictFromJSONFile,
    getFilePathsInDirectory,
    getStringFromFile,
    tryTo,
)

from model import (
    Host,
    HostService,
)

from query_manager import (
    setConfigFile,
    getConfig,
    getDBSession,
)

ADDRESS_DATA_DIR_PATH = None

def setAddressDataDirPath(path):
    global ADDRESS_DATA_DIR_PATH
    ADDRESS_DATA_DIR_PATH = path

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

def getHostRowFromDict(dict):
    return {
        "address": getAttrFromDict(dict, "ip_str"),
        "country": getAttrFromDict(dict, "country_code"),
        "provider": getAttrFromDict(dict, "org"),
        "isp": getAttrFromDict(dict, "isp"),
    }

def createRowOrCompleteInfo(hostRow, session):
    hostObject = session.get(Host, hostRow["address"])
    if hostObject is None:
        hostObject = Host(**hostRow)
        session.add(hostObject)
    else:
        for key, value in hostRow.items():
            if getattr(hostObject, key) is not None:
                setattr(hostObject, key, value)

def getAllRowDicts():
    filePaths = getFilePathsInDirectory(ADDRESS_DATA_DIR_PATH)
    allHostRows = map(
        lambda filePath: getHostRowFromDict(tryTo(eval(getStringFromFile(filePath)), {})),
        filePaths
    )

    return filter(
        lambda hostRow: hostRow["address"] is not None,
        allHostRows
    )

def completeHostTable():
    session = getDBSession()

    for hostRow in getAllRowDicts(ADDRESS_DATA_DIR_PATH):
        createRowOrCompleteInfo(hostRow, session)
    
    session.commit()
    session.close()
