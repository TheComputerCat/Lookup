import os
import datetime
import re
import sys
import xml.etree.ElementTree as XML
import src.common.query_manager as query_manager

from src.common.common import (
    formatDirPath,
    formatFilePath,
    log,
    getFilePathsInDirectory,
)

from src.common.model import (
    HostService,
    Service,
    Host,
)
    
def getHostElementFromXML(xml_path: str):

    xml_file = formatFilePath(xml_path)
    root = XML.parse(xml_file).getroot()
    return root.find('host')

def getAllHostServices(host_element, host_object):
    services = []
    host_address = getAddress(host_element)
    host_timestamp = getTimeStamp(host_element)
    for port_element in host_element.iter('port'):
        service_element = port_element.find('service')
        state = port_element.find('state').attrib.get('state')
        if ServiceIsUnknow(port_element) or state != 'open':
            continue
        unique_service_object = getOrCreateService(service_element)
        services.append(getHostServiceDict(port_element, host_address, host_timestamp, host_object, unique_service_object))
                
    services = filter(lambda host_service_dict : not query_manager.searchInTable(HostService,getSearchableHostServiceDict(host_service_dict)),services)
    services = list(map(lambda service : HostService(**service),services))
    return services
   
def getSearchableHostServiceDict(host_service_dict):
    return {
          'address': host_service_dict['address'],
          'source': 'nmap',
          'protocol': host_service_dict['protocol'],
          'port': host_service_dict['port'],
          }

def getSearchableHostServiceDict(host_service_dict):
    return {
          'address': host_service_dict['address'],
          'source': 'nmap',
          'protocol': host_service_dict['protocol'],
          'port': host_service_dict['port'],
          }

def ServiceIsUnknow(port_element):
    service_name = getServiceName(port_element.find('service')).strip().lower()
    return (not service_name) or service_name == 'unknown' 

def getHostServiceDict(port_element, host_address, host_timestamp, host_object,unique_service_object):
    return {
          'address': host_address,
          'source': 'nmap',
          'protocol': getProtocol(port_element),
          'port': getPortNumber(port_element),
          'timestamp': host_timestamp,
          'service': unique_service_object,
          'host': host_object,
    }

def getProtocol(port_element):
    return port_element.attrib.get('protocol')

def getPortNumber(port_element):
    return int(port_element.attrib.get('portid'))

def getTimeStamp(host_element):
    return datetime.datetime.fromtimestamp(int(host_element.attrib.get('starttime')))

def insertNewServiceInDB(service_dict):
    service_object = Service(**service_dict)
    query_manager.insert(service_object)
    return service_object

def getUniqueServiceDict(service_element):
    return {
          'name': getServiceName(service_element),
          'version': getServiceVersion(service_element),
          'cpe_code': getServiceCPECode(service_element),
    }

def getSearchableUniqueServiceDict(service_dict):
    return {
          'name': service_dict['name'],
          'version': service_dict['version'],
          }

def getServiceName(service_element):
    product_name = service_element.attrib.get('product')
    if product_name:
        return product_name
    return service_element.attrib.get('name')

def getServiceCPECode(service_element):
    cpe_element = service_element.find('cpe')
    if cpe_element != None:
        return cpe_element.text

def getOrCreateService(service_element):
    service_dict = getUniqueServiceDict(service_element)
    found_service_object = query_manager.searchInTable(Service,getSearchableUniqueServiceDict(service_dict))
    if not found_service_object :
        return insertNewServiceInDB(service_dict)
    return found_service_object

def getServiceVersion(service_element):
    product_version = service_element.attrib.get('version')
    if product_version:
        return product_version
    service_info = service_element.attrib.get('servicefp',"")
    search = re.findall("(?<=V=)(.*)(?=%I)",service_info)
    if search:
        return search[0]
    return 

def getHostDictFromXMLHost(host_element):
    return {
        'address':getAddress(host_element),
    }

def completeTables(xml_path: str):
    host_element = getHostElementFromXML(xml_path)
    host_dict = getHostDictFromXMLHost(host_element)
    host_object = Host(**host_dict)
    host_found_in_db = query_manager.searchInTable(Host,host_dict)
    if not host_found_in_db:
        query_manager.insert(host_object)
    else:
        host_object = host_found_in_db
    for host_service in  getAllHostServices(host_element,host_object):
            query_manager.insert(host_service)
            query_manager.insert(host_service)

def getAddress(host_element):
    return host_element.find('address').attrib['addr']

def isInfoFile(file_path):
    file_name = file_path.split("/").pop()
    return os.path.isfile(file_path) and file_name.find('std') == -1 and (file_name.find('-udp-') != -1 or file_name.find('-tcp-') != -1)

def getCorrectFilePathsInDirectory(path):
    return list(filter( lambda file_path: isInfoFile(file_path) ,getFilePathsInDirectory(path)))

def completeTablesWithFilesFromPath(path):
    for file_path in getCorrectFilePathsInDirectory(path):
        completeTables(file_path)

if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) < 2:
        raise Exception("""Se necesitan dos argumentos:
    1. la ruta al archivo con las credenciales de la base de datos,
    2. La ruta al directorio con la información de hosts de Nmap.""")

    configFile = formatFilePath(args[0])
    dataDirPath = formatDirPath(args[1])

    query_manager.setConfigFile(configFile)

    completeTablesWithFilesFromPath(dataDirPath)
    