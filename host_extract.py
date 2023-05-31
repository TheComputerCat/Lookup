from common import (
    getDictFromJSONFile,
    getFilePathsInDirectory,
    getStringFromFile,
    tryTo,
)

from model import (
    Host,
    HostService,
    Service,
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
        "address": getAttrFromDict(dict, "ip_str"),
        "country": getAttrFromDict(dict, "country_code"),
        "provider": getAttrFromDict(dict, "org"),
        "isp": getAttrFromDict(dict, "isp"),
        "ports": getListFromDict(dict, 'ports'),
        "services": getServicesFromDict(dict),
    }

def getServiceRowFromServiceDict(serviceDict):
    return {
        "name": getAttrFromDict(serviceDict, "service"),
        "version": getAttrFromDict(serviceDict, "version"),
        "cpe_code": tryTo(lambda: serviceDict["cpe23"][0], None),
    }

def getHostRowFromHostInfoDict(dict):
    return {
        "address": getAttrFromDict(dict, "address"),
        "country": getAttrFromDict(dict, "country"),
        "provider": getAttrFromDict(dict, "provider"),
        "isp": getAttrFromDict(dict, "isp"),
    }

def completeObjectInfo(obj, row):
    for key, value in row.items():
        if getattr(obj, key) is None:
            setattr(obj, key, value)

def createHostRowOrCompleteInfo(hostRow, session):
    hostObject = session.get(Host, hostRow["address"])
    if hostObject is None:
        hostObject = Host(**hostRow)
        session.add(hostObject)
    else:
        completeObjectInfo(hostObject, hostRow)
    
    session.commit()

def getAllHostInfoDicts():
    filePaths = getFilePathsInDirectory(ADDRESS_DATA_DIR_PATH)
    allHostRows = map(
        lambda filePath: getHostInfoFromDict(tryTo(eval(getStringFromFile(filePath)), {})),
        filePaths
    )

    return filter(
        lambda hostRow: hostRow["address"] is not None,
        allHostRows
    )

def completeHostTable():
    session = getDBSession()

    for row in getAllHostInfoDicts():
        createHostRowOrCompleteInfo(getHostRowFromHostInfoDict(row), session)
    
    session.commit()
    session.close()

def createServiceRowIfNeeded(serviceDict, session):
    serviceRow = getServiceRowFromServiceDict(serviceDict)

    serviceObject = session.query(Service).filter_by(
        **serviceRow
    ).first()

    if serviceObject is None:
        session.add(
            Service(
                **serviceRow
            )
        )
    
    session.commit()

def completeServiceTable():
    session = getDBSession()

    for dict in getAllHostInfoDicts():
        for serviceDict in dict["services"]:
            createServiceRowIfNeeded(serviceDict, session)
    
    session.close()

def completeHostServiceTable():
    session = getDBSession()

    for dict in getAllHostInfoDicts():
        address = dict["address"]
        for serviceDict in dict["services"]:
            serviceRow = getServiceRowFromServiceDict(serviceDict)

            serviceObject = session.query(Service).filter_by(
                **serviceRow
            ).first()

            session.add(
                HostService(
                    address=address,
                    service=serviceObject,
                    source="shodan",
                    timestamp=serviceDict["timestamp"]
                )
            )
    
            session.commit()
    
    session.close()
