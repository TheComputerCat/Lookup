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
        if ServiceIsUnknow(port_element):
            pass
        services.append(getHostServiceDict(port_element,host_address,host_timestamp))
    return map(lambda service :HostService(**service),services)

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

def getServiceIdIfExist(service_dict):
    found_service = query_manager.searchInTable(Service,service_dict)
    if not found_service:
        return None
    return found_service.id

def getServiceIfExist(service_dict):
    found_service = query_manager.searchInTable(Service,service_dict)
    if not found_service:
        return None
    return found_service

def getIdOfNewServiceInDB(service_dict):
    query_manager.insert(Service(**service_dict))
    return getServiceIdIfExist(service_dict)

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
    print(service_object)
    return service_object.id

def getService(service_element):
    service_dict = getUniqueServiceDict(service_element)
    found_service_object = getServiceIfExist(service_dict)
    print('found',found_service_object)
    if found_service_object is None:
        service_object = Service(**service_dict)
        insertNewServiceInDB(service_object)
        print('service created', service_object)
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
    query_manager.insertMany(services_in_host)
    return {
        'address':getAddress(host_element),
        'services_in_host': services_in_host,
    }

def getAddress(host_element):
    return host_element.find('address').attrib['addr']

if __name__ == "__main__":
    print(getHostElementFromXML('./data_2/example'))