from common import (
    tryTo,
    formatDirPath,
    getStringFromFile,
    formatFilePath
)

from model import (
    HostService,
)

import os
import datetime

import xml.etree.ElementTree as XML


def getHostElementFromXML(xml_path: str):

    xml_file = formatFilePath(xml_path)
    root = XML.parse(xml_file).getroot()
    return root.find('host')

def getAllHostServices(host_element):
    services = []
    host_address = getAddress(host_element)
    host_timestamp = getTimeStamp(host_element)
    for port in host_element.iter('port'):
        services.append(getHostServiceDict(port.find('service')),host_address,host_timestamp)
    services = filterUnknownServices(services)
    return map(lambda service :HostService(**service),services)
    
def filterUnknownServices(services):
    return [service for service in services if service['name'] != 'unknown']

def getHostServiceDict(service_element, host_address, host_timestamp):
    service_dict = getUniqueServiceDict(service_element)
    service_id = getServiceIdIfExist(service_dict)
    if not service_id:
        service_id = insertNewServiceInDB(service_dict)
    return {
          'address': host_address,
          'service_id': service_id,
          'source': 'nmap',
          'timestamp': host_timestamp
    }

def getServiceIdIfExist(service_element):
    # recorre la base de datos
    # encuentra el id si el servicio esta registrado, en otro caso retorna null
    return None

def insertNewServiceInDB(service_dict):
    return 0


def getTimeStamp(host_element):
    return datetime.datetime.fromtimestamp(int(host_element.attrib['starttime']))

def getUniqueServiceDict(service_element):
    return {
          'name': service_element.attrib['name'],
          'version': tryTo(getServiceVersion(service_element),'0.0.0')
    }

def getServiceVersion(service_element):
    return service_element.attrib['servicefp']

def getHostDictFromXML(xml_path: str):
    host_element = getHostElementFromXML(xml_path)
    return {
        'address':getAddress(host_element),
        'services_in_host': getAllHostServices(host_element),
    }

def getAddress(host_element):
    return host_element.find('address').attrib['addr']

if __name__ == "__main__":
    print(getHostElementFromXML('./data_2/example'))