from common import (
    formatDirPath,
    formatFilePath,
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
    getDBSession,
)

import sys

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
        "protocol": getAttrFromDict(dict, "transport"),
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
        "address": address,
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
        lambda filePath: getHostInfoFromDict(tryTo(lambda: eval(getStringFromFile(filePath)), {})),
        filePaths
    )

    return filter(
        lambda hostRow: "address" in hostRow,
        allHostRows
    )

def getHostRows():
    return map(
        getHostRowFromHostInfoDict,
        getAllHostInfoDicts()
    )

def completeHostTable():
    session = getDBSession()

    for hostRow in getHostRows():
        createHostRowOrCompleteInfo(hostRow, session)
    
    session.commit()
    session.close()

def getNewServiceRows(session):
    for dict in getAllHostInfoDicts():
        for serviceDict in dict["services"]:
            serviceRow = getServiceRowFromServiceDict(serviceDict)

            serviceObject = session.query(Service).filter_by(
                **serviceRow
            ).first()

            if serviceObject is None:
                yield serviceRow

def completeServiceTable():
    session = getDBSession()

    for serviceRow in getNewServiceRows(session):
        session.add(Service(**serviceRow))

    session.commit()
    session.close()

def getHostServiceRows(session):
    for dict in getAllHostInfoDicts():
        address = dict["address"]
        for serviceDict in dict["services"]:
            serviceRow = getServiceRowFromServiceDict(serviceDict)
            serviceObject = session.query(Service).filter_by(
                **serviceRow
            ).first()

            row = {
                "address": address,
                "service": serviceObject,
                "source": "shodan-host",
                "protocol": getAttrFromDict(serviceDict, "protocol"),
                "timestamp": serviceDict["timestamp"],
            }

            yield row


def completeHostServiceTable():
    session = getDBSession()

    for hostServiceRow in getHostServiceRows(session):
        session.add(HostService(**hostServiceRow))
    
    session.commit()
    session.close()

if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) < 2:
        raise Exception("""Se necesitan dos argumentos:
    1. la ruta al archivo con las credenciales de la base de datos,
    2. La ruta al directorio con la información de hosts de Shodan.""")

    configFile = formatFilePath(args[0])
    dataDirPath = formatDirPath(args[1])

    setConfigFile(configFile)
    setAddressDataDirPath(dataDirPath)

    completeServiceTable()
    completeHostTable()
    completeHostServiceTable()
