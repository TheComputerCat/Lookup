from common import (
    tryTo,
    formatDirPath,
    getStringFromFile,
    formatFilePath
)

from model import (
    HostService,
    Service
)

import query_manager

import os
import datetime
import re

import xml.etree.ElementTree as XML


def getHostElementFromXML(xml_path: str):

    xml_file = formatFilePath(xml_path)
    root = XML.parse(xml_file).getroot()
    return root.find('host')

def getAllHostServices(host_element):
    services = []
    host_address = getAddress(host_element)
    host_timestamp = getTimeStamp(host_element)
    for port_element in host_element.iter('port'):
        service_in_port = port_element.find('service')
        services.append(getHostServiceDict(service_in_port,host_address,host_timestamp))
    services = filterUnknownServices(services)
    return map(lambda service :HostService(**service),services)
    
def filterUnknownServices(services):
    return [service for service in services if service['name'] != 'unknown']

def getHostServiceDict(service_element, host_address, host_timestamp):
    service_dict = getUniqueServiceDict(service_element)
    service_id = getServiceIdIfExist(service_dict)
    if service_id is None:
        service_id = insertNewServiceInDB(service_dict)
    return {
          'address': host_address,
          'service_id': service_id,
          'source': 'nmap',
          'timestamp': host_timestamp
    }

def getServiceIdIfExist(service_dict):
    found_service = query_manager.searchInTable(Service,service_dict)
    if not found_service:
        return None
    return found_service.id

def insertNewServiceInDB(service_dict):
    query_manager.insert(Service(**service_dict))
    return getServiceIdIfExist(service_dict)


def getTimeStamp(host_element):
    return datetime.datetime.fromtimestamp(int(host_element.attrib['starttime']))

def getUniqueServiceDict(service_element):
    service_info = service_element.attrib.get('servicefp',"")
    return {
          'name': service_element.attrib.get('name'),
          'version': getServiceVersion(service_info)
    }

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

def getAddress(host_element):
    return host_element.find('address').attrib['addr']

if __name__ == "__main__":
    print(getHostElementFromXML('./data_2/example'))