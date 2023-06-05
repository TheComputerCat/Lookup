from common import (
    formatDirPath,
    formatFilePath,
    log,
    getStringFromFile
)

from model import (
    HostService,
    Service,
    Host
)

import query_manager
import os
import datetime
import re
import sys

import xml.etree.ElementTree as XML

ADDRESS_DATA_DIR_PATH = None

def setAddressDataDirPath(path):
    global ADDRESS_DATA_DIR_PATH
    ADDRESS_DATA_DIR_PATH = path
    
def getHostElementFromXML(xml_path: str):

    xml_file = formatFilePath(xml_path)
    root = XML.parse(xml_file).getroot()
    return root.find('host')

def getAllHostServices(host_element):
    services = []
    host_address = getAddress(host_element)
    host_timestamp = getTimeStamp(host_element)
    for port_element in host_element.iter('port'):
        if ServiceIsUnknow(port_element):
            pass
        services.append(getHostServiceDict(port_element,host_address,host_timestamp))
    services = list(map(lambda service : HostService(**service),services))
    return services

def ServiceIsUnknow(port_element):
    service_name = getServiceName(port_element.find('service'))
    return not service_name or service_name == 'unknown' 

def getHostServiceDict(port_element, host_address, host_timestamp):
    service_element = port_element.find('service')
    unique_service_object = getService(service_element)
    return {
          'address': host_address,
          'source': 'nmap',
          'protocol': getProtocol(port_element),
          'timestamp': host_timestamp,
          'service': unique_service_object,
    }

def getProtocol(port_element):
    return port_element.attrib['protocol']

def getTimeStamp(host_element):
    return datetime.datetime.fromtimestamp(int(host_element.attrib['starttime']))

def getServiceIfExist(service_dict):
    found_service = query_manager.searchInTable(Service,service_dict)
    if not found_service:
        return None
    return found_service

def insertNewServiceInDB(service_object):
    query_manager.insert(service_object)

def getUniqueServiceDict(service_element):
    service_info = service_element.attrib.get('servicefp',"")
    return {
          'name': getServiceName(service_element),
          'version': getServiceVersion(service_info)
    }

def getServiceName(service_element):
    return service_element.attrib.get('name')

def getServiceId(service_object):
    return service_object.id

def getService(service_element):
    service_dict = getUniqueServiceDict(service_element)
    found_service_object = getServiceIfExist(service_dict)
    if found_service_object is None:
        service_object = Service(**service_dict)
        # insertNewServiceInDB(service_object)
        return service_object
    return found_service_object

def getServiceVersion(service_info):
    search = re.findall("(?<=V=)(.*)(?=%I)",service_info)
    if search:
        return search[0]
    return 

def getHostDictFromXML(xml_path: str):
    host_element = getHostElementFromXML(xml_path)
    services_in_host = getAllHostServices(host_element)
    return {
        'address':getAddress(host_element),
        'services_in_host': services_in_host,
    }

def completeTables(xml_path):
    host_dict = getHostDictFromXML(xml_path)
    if not query_manager.searchInTable(Host,{'address' : host_dict['address'],}):
        query_manager.insert(Host(**host_dict))
        print('succesfull host insertion')
    else:
        print('host is already in db, inserting new services')
        query_manager.insertMany(host_dict['services_in_host'])

def setConfigFile(configFilePath):
    global CONFIG_FILE_PATH
    try:
        if not os.path.exists(configFilePath):
            raise Exception(f'{configFilePath} file do not exist')
        CONFIG_FILE_PATH = configFilePath
    except Exception as e:
        log(e, debug=True, printing=True) 

def getAddress(host_element):
    return host_element.find('address').attrib['addr']

def getFilePathsInDirectory(directoryPath):
    fixedDirPath = formatDirPath(directoryPath)
    return [
        fixedDirPath+fileName for fileName in os.listdir(fixedDirPath)
        if isInfoFile(fixedDirPath+fileName,fileName)
    ]

def isInfoFile(file_path,file_name):
    return os.path.isfile(file_path) and file_name.find('std') == -1 and (file_name.find('-udp-') != -1 or file_name.find('-tcp-') != -1)

if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) < 2:
        raise Exception("""Se necesitan dos argumentos:
    1. la ruta al archivo con las credenciales de la base de datos,
    2. La ruta al directorio con la información de hosts de Nmap.""")

    configFile = formatFilePath(args[0])
    dataDirPath = formatDirPath(args[1])

    query_manager.setConfigFile(configFile)
    setAddressDataDirPath(dataDirPath)

    for file_path in getFilePathsInDirectory(ADDRESS_DATA_DIR_PATH):
        print(file_path)
        completeTables(file_path)
    # print(getStringFromFile('./data/nmap_data/332e31332e3230372e37-tcp-std-2023 05 25-00 52 33'))
    # XML.parse('./data/nmap_data/332e31332e3230372e37-tcp-std-2023 05 25-00 52 33').getroot()



