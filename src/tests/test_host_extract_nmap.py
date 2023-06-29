import unittest
import datetime
import src.extract.host_extract_nmap as host_extract_nmap
import src.common.query_manager as query_manager

from sqlalchemy import create_engine
from testcontainers.postgres import PostgresContainer
from unittest.mock import (
    patch,
    Mock,
)
from src.common.model import (
    HostService,
    Service,
    Host
)
from src.common.common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

def setUpDatabase(postgres):
    postgres.start()
    query_manager.createTables()

def tearDownDatabase(postgres):
    postgres.stop()

def getDBEngineStub(postgresContainer):
    return lambda: create_engine(postgresContainer.get_connection_url())

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)
withTestDataBase = createFixture(setUpDatabase, tearDownDatabase)

XMLContentExample = r"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
<host starttime="1684970000" endtime="1684970001">
<hostnames>
<hostname name="pepe.com" type="PTR"/>
</hostnames>
<address addr='012.345.678.901'/>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="8008"><state state="open" /><service name="https" servicefp="SF-Port8008-TCP:V=7.80%I=2%D=5/25%Time=646EB137%P=x86_64-pc-linux-gnu%r(GetRequest,D3,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015/\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;)%r(FourOhFourRequest,F6,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015/nice%20ports%2C/Tri%6Eity\.txt%2ebak\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;)%r(GenericLines,D2,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;);" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>"""

XMLContentWithCPEExample = r"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
<host starttime="1684970000" endtime="1684970001">
<hostnames>
<hostname name="pepe.com" type="PTR"/>
</hostnames>
<address addr='012.345.678.901'/>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="nginx" version="1.9.4" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" method="table" conf="3"><cpe>cpe:/a:apache:http_server</cpe></service></port>
<port protocol="tcp" portid="8008"><state state="open" /><service name="https" servicefp="SF-Port8008-TCP:V=7.80%I=2%D=5/25%Time=646EB137%P=x86_64-pc-linux-gnu%r(GetRequest,D3,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015/\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;)%r(FourOhFourRequest,F6,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015/nice%20ports%2C/Tri%6Eity\.txt%2ebak\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;)%r(GenericLines,D2,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;);" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>"""

class TestHelpers(unittest.TestCase):
    postgresContainer = PostgresContainer("postgres:latest")

    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    def test_getHostElementFromXML(self):
        result_host = host_extract_nmap.getHostElementFromXML('./data/host1')
        self.assertEqual(result_host.tag,'host')

    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @patch('src.extract.host_extract_nmap.getOrCreateService', new_callable=Mock, return_value=Service(**{'id' : 25, 'name' : 'https',}))
    def test_getHostServiceDict_without_ids(self,getServiceIfExist):
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        expected_dict = {
            'address': '8.8.8.8',
            'service_id': 0,
            'source': 'nmap',
            'protocol': 'tcp',
            'timestamp': datetime.datetime.now()
            }
        host_object = Host(**{'address': '8.8.8.8'})
        for port_element in host_element.iter('port'):
            host_service_dict = host_extract_nmap.getHostServiceDict(port_element, '8.8.8.8', datetime.datetime.now(), host_object, Service(**{ 'name': 'ftp', 'version': None}))
            self.assertEqual(host_service_dict['address'],expected_dict['address'])
            self.assertEqual(host_service_dict['source'],expected_dict['source'])
            self.assertEqual(host_service_dict['protocol'],expected_dict['protocol'])

    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @withTestDataBase(postgres=postgresContainer)
    def test_getHostServiceDict_with_service(self, mockCreateEngine):
        session = query_manager.getDBSession()
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        host_object = Host(**{'address': '8.8.8.8'})
        for port_element in host_element.iter('port'):
            host_service_dict = host_extract_nmap.getHostServiceDict(port_element,'8.8.8.8',datetime.datetime.now(),host_object, Service(**{ 'name': 'ftp', 'version': None}))
            self.assertIsNotNone(host_service_dict['service'])

    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    def test_getUniqueServiceDict(self):
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        unique_services = [{
          'name': 'ftp',
          'version': None,
          'cpe_code': None
        },{
          'name': 'http',
          'version': None,
          'cpe_code': None
        },{
          'name': 'https',
          'version': '7.80',
          'cpe_code': None
        }]
        for index, port_element in enumerate(host_element.iter('port')):
            expected_dict = unique_services[index]
            self.assertDictEqual(host_extract_nmap.getUniqueServiceDict(port_element.find('service')),expected_dict) 

    @withATextFile(pathToTextFile='./data/host1', content=XMLContentWithCPEExample)
    def test_getUniqueServiceDictWithCPE(self):
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        unique_services = [{
          'name': 'nginx',
          'version': '1.9.4',
          'cpe_code': None
        },{
          'name': 'Apache httpd',
          'version': None,
          'cpe_code': 'cpe:/a:apache:http_server'
        },{
          'name': 'https',
          'version': '7.80',
          'cpe_code': None
        }]
        for index, port_element in enumerate(host_element.iter('port')):
            expected_dict = unique_services[index]
            self.assertDictEqual(host_extract_nmap.getUniqueServiceDict(port_element.find('service')),expected_dict)  

    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @withTestDataBase(postgres=postgresContainer)
    def test_insertNewServiceInDB(self, mockCreateEngine):
        session = query_manager.getDBSession()
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        for port_element in host_element.iter('port'):
            service_dict = host_extract_nmap.getUniqueServiceDict(port_element.find('service'))
            host_extract_nmap.insertNewServiceInDB(service_dict)
        self.assertEqual(len(session.query(Service).all()),3)
        session.close()

    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentWithCPEExample)
    @withTestDataBase(postgres=postgresContainer)
    def test_insertNewServiceWithCPEInDBWhenServiceExist(self, mockCreateEngine):
        session = query_manager.getDBSession()
        query_manager.insert(Service(**{'name' : 'nginx', 'version': '1.9.4' ,}))
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        for port_element in host_element.iter('port'):
            host_extract_nmap.getOrCreateService(port_element.find('service'))
        self.assertEqual(len(session.query(Service).all()),3)
        session.close()

    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @withTestDataBase(postgres=postgresContainer)
    def test_insertNewServiceInDB_when_service_exist(self, mockCreateEngine):
        session = query_manager.getDBSession()
        query_manager.insert(Service(**{'name' : 'ftp', 'version': None ,}))
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        for port_element in host_element.iter('port'):
            host_extract_nmap.getOrCreateService(port_element.find('service'))
        self.assertEqual(len(session.query(Service).all()),3)
        session.close()
    
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @withTestDataBase(postgres=postgresContainer)
    def test_insertHostServiceInDB_when_service_exist(self, mockCreateEngine):
        session = query_manager.getDBSession()
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        query_manager.insert(Service(**{'name' : 'ftp', 'version': None ,}))
        host_object = Host(**{'address': '012.345.678.901'})
        host_services = host_extract_nmap.getAllHostServices(host_element, host_object)
        query_manager.insertMany(host_services)
        self.assertEqual(len(session.query(Service).all()),3)
        self.assertEqual(len(session.query(HostService).all()),3)
        session.close()
    
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @withTestDataBase(postgres=postgresContainer)
    def test_getAllHostServices(self, mockCreateEngine):
        session = query_manager.getDBSession()
        host_element = host_extract_nmap.getHostElementFromXML('./data/host1')
        host_object = Host(**{'address': '012.345.678.901'})
        host_services = host_extract_nmap.getAllHostServices(host_element, host_object)
        for host_service in host_services:
            self.assertEqual(type(host_service),HostService)
            self.assertEqual(host_service.address,host_extract_nmap.getAddress(host_element))
            self.assertEqual(host_service.protocol,'tcp')
            self.assertEqual(host_service.source,'nmap')
            self.assertIsNotNone(host_service.port)
        session.close()

    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    @patch('src.extract.host_extract_nmap.getAllHostServices', new_callable=Mock, return_value=[Service(**{'id' : 25, 'name' : 'https',})])
    def test_getHostDictFromXMLHost(self,getAllHostServices):
        host_dict = host_extract_nmap.getHostDictFromXMLHost(host_extract_nmap.getHostElementFromXML('./data/host1'))
        self.assertEqual(host_dict['address'],'012.345.678.901')

    @withATextFile(pathToTextFile='./data1/12345abc-tcp-2023:05:25', content=XMLContentExample)
    @withATextFile(pathToTextFile='./data1/12345abc-tcp-std-2023:05:30', content='fooled')
    def test_isInfoFile(self):
        self.assertTrue(host_extract_nmap.isInfoFile('./data1/12345abc-tcp-2023:05:25','12345abc-tcp-2023:05:25'))
        self.assertFalse(host_extract_nmap.isInfoFile('./data1/12345abc-tcp-std-2023:05:30','12345abc-tcp-std-2023:05:30'))

class TestAcceptance(unittest.TestCase):
    postgresContainer = PostgresContainer("postgres:latest")

    hostDictExample = {
        'address': '012.345.678.901',
    }
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @patch('src.extract.host_extract_nmap.getHostDictFromXMLHost', new_callable=Mock, return_value= hostDictExample )
    @withTestDataBase(postgres=postgresContainer)
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    def test_completeTables(self,getHostDictFromXMLHost, mockCreateEngine):
        session = query_manager.getDBSession()
        host_extract_nmap.completeTables('./data/host1')
        self.assertEqual(len(query_manager.getAllFromClass(Host)),1)
        self.assertEqual(len(query_manager.getAllFromClass(Service)),3)
        self.assertEqual(len(query_manager.getAllFromClass(HostService)),3)
        session.close()
    
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @patch('src.extract.host_extract_nmap.getHostDictFromXMLHost', new_callable=Mock, return_value= hostDictExample )
    @withTestDataBase(postgres=postgresContainer)
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    def test_completeTables_whenServiceExist(self,getHostDictFromXMLHost, mockCreateEngine):
        session = query_manager.getDBSession()
        query_manager.insert(Service(**{'name' : 'ftp', 'version': None}))
        host_extract_nmap.completeTables('./data/host1')
        self.assertEqual(len(query_manager.getAllFromClass(Host)),1)
        self.assertEqual(len(query_manager.getAllFromClass(HostService)),3)
        self.assertEqual(len(query_manager.getAllFromClass(Service)),3)
        session.close()

    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @patch('src.extract.host_extract_nmap.getHostDictFromXMLHost', new_callable=Mock, return_value= hostDictExample )
    @withTestDataBase(postgres=postgresContainer)
    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    def test_completeTables_whenHostAndServiceExist(self,getHostDictFromXMLHost, mockCreateEngine):
        session = query_manager.getDBSession()
        query_manager.insert(Service(**{'name' : 'ftp', 'version': None}))
        query_manager.insert(Host(**{'address' : '012.345.678.901'}))
        host_extract_nmap.completeTables('./data/host1')
        self.assertEqual(len(query_manager.getAllFromClass(Host)),1)
        self.assertEqual(len(query_manager.getAllFromClass(HostService)),3)
        self.assertEqual(len(query_manager.getAllFromClass(Service)),3)
        session.close()

if __name__ == "__main__":
    unittest.main()
