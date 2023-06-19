import unittest
import src.extract.domain_extract as domain_extract
import json
from datetime import datetime

from unittest.mock import (
    patch,
    Mock,
)

from src.tests.domain_extract_fixtures import (
    shodanJson1,
    shodanJson2,
    filteredShodanJson1,
    filteredShodanJson2,
    filteredJoinedShodanJson1AndJson2,
    filteredShodanJson1WithObjects
)

from src.common.common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

import src.common.model as md
from testcontainers.postgres import PostgresContainer
from sqlalchemy import create_engine
import src.common.query_manager as query_manager

from copy import deepcopy

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestGetJson(unittest.TestCase):
    filePath = './data/domain_raw_data/file1'
    @withATextFile(pathToTextFile=filePath, content='{"someKey": "someValue"}')
    @patch('src.extract.domain_extract.open', new_callable=Mock, wraps=open)
    def test_getJsonFromFile_withAExistingFile(self, spyOpen, content):
        """
            Read json from path
        """
        json_ = domain_extract.getJsonFromFile(self.filePath)

        spyOpen.assert_called_once_with(self.filePath, 'r')
        self.assertDictEqual(json_, json.loads(content))
    
    def test_getJsonFromFile_withAUnexistentFile(self):
        """
            Read json from nonexisting path
        """
        json_ =domain_extract.getJsonFromFile(self.filePath)
        self.assertDictEqual(json_, {})

class TestGetData(unittest.TestCase):
    shodanJsonList = [shodanJson1, shodanJson2]

    def test_filterDataFomJson_withAExistingFile(self):
        """
            Get Data from a json dictionary from shodan
        """
        filteredJsonResponse = domain_extract.filterJson(shodanJson1)

        self.maxDiff = None

        self.assertDictEqual(filteredJsonResponse, filteredShodanJson1)
    
    def test_filterJsonList_withAnArrayOfJson(self):
        """
            Get array of filtered data from a array of JSON
        """

        filteredJsonResponse = domain_extract.filterFromJsonList(self.shodanJsonList)

        self.maxDiff = None

        self.assertDictEqual(filteredJsonResponse, filteredJoinedShodanJson1AndJson2)


class TestExtractDataFromFolder(unittest.TestCase):
    pathFile1 = './data/domain_raw_data/file1'

    jsonInFile1 = f'[{json.dumps(shodanJson1)},{json.dumps(shodanJson2)}]'

    @withATextFile(pathToTextFile=pathFile1, content=jsonInFile1)
    def test_extractDataFromFile_fromAFile(self):
        """
            From a file containing a shodan response, an array of two json, 
            extractDataFromFile returns an array of the filtered data from each
            json.
        """

        jsonReposesList = domain_extract.extractDataFromFile(self.pathFile1)

        self.maxDiff = None

        self.assertDictEqual(jsonReposesList, filteredJoinedShodanJson1AndJson2)

    pathFile2 = './data/domain_raw_data/file2'
    pathFile3 = './data/domain_raw_data/file3'

    jsonInFile2 = f'[{json.dumps(shodanJson1)},{json.dumps(shodanJson2)}]'
    jsonInFile3 = f'[{json.dumps(shodanJson2)}]'

    filteredDataInFolder = [filteredJoinedShodanJson1AndJson2, filteredShodanJson2]

    folderPath = './data/domain_raw_data/'

    @withATextFile(pathToTextFile=pathFile3, content=jsonInFile3)
    @withATextFile(pathToTextFile=pathFile2, content=jsonInFile2, deleteFolder=False)
    def test_extractDataFromFolder_fromAFolderWithTwoFiles(self):

        dataListFromFolder = domain_extract.extractDataFromFolder(self.folderPath)

        self.maxDiff = None

        for i in range(0, 2):
            with self.subTest(i=i):
                self.assertDictEqual(dataListFromFolder[i], self.filteredDataInFolder[i])

class TestObjectRMCCreation(unittest.TestCase):
    def test_ORMobjectsComparison(self):
        """
            Ensure equality assertions on plain model objects (with no other objects as attributes) 
            are correct. 
        """
        host1 = md.Host(address='8.8.8.8', country='A nice country', provider='A company', isp='A isp')
        host2 = md.Host(address='8.8.8.8', country='A nice country', provider='A company', isp='A isp')
        host3 = md.Host(address='8.8.8.8', country='A less nice country', provider='A company', isp='A isp')

        self.assertEqual(host1, host2)
        self.assertNotEqual(host2, host3)

        ARecord1 = md.ARecord(id=1, ip_address='8.8.8.8', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))
        ARecord2 = md.ARecord(id=1, ip_address='8.8.8.8', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))
        ARecord3 = md.ARecord(id=2, ip_address='8.8.8.8', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))

        self.assertEqual(ARecord1, ARecord2)
        self.assertNotEqual(ARecord2, ARecord3)

        MXRecord1 = md.MXRecord(id=1, domain='adomain.com', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))
        MXRecord2 = md.MXRecord(id=1, domain='adomain.com', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))
        MXRecord3 = md.MXRecord(id=1, domain='adifferentdomain.com', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))

        self.assertEqual(MXRecord1, MXRecord2)
        self.assertNotEqual(MXRecord2, MXRecord3)

        TXTRecord1 = md.TXTRecord(id=1, content='some content', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))
        TXTRecord2 = md.TXTRecord(id=1, content='some content', parent_domain_info_id=1, timestamp=datetime(2000, 1, 1))
        TXTRecord3 = md.TXTRecord(id=1, content='some content', parent_domain_info_id=2343, timestamp=datetime(2000, 1, 1))

        self.assertEqual(TXTRecord1, TXTRecord2)
        self.assertNotEqual(TXTRecord2, TXTRecord3)

        domainInfo1 = md.DomainInfo(id=1, domain='', subdomain=False, main_domain_id=1)
        domainInfo2 = md.DomainInfo(id=1, domain='', subdomain=False, main_domain_id=1)
        domainInfo3 = md.DomainInfo(id=12, domain='someSubdomain.org', subdomain=False, main_domain_id=1)

        self.assertEqual(domainInfo1, domainInfo2)
        self.assertNotEqual(domainInfo2, domainInfo3)

        mainDomain1 = md.MainDomain(id=1, name='somedomain.org', organization_id=1)
        mainDomain2 = md.MainDomain(id=1, name='somedomain.org', organization_id=1)
        mainDomain3 = md.MainDomain(id=1, name='otherdomain.org', organization_id=1)

        self.assertEqual(mainDomain1, mainDomain2)
        self.assertNotEqual(mainDomain2, mainDomain3)

    def test_convertToOrmObjects_fromFilteredJsonCreateObjects(self):
        """
            When a filtered Json is given, a new json is returned
            with the data converted to the ORM objects.
        """

        self.maxDiff = None
        jsonWithOrmObjects = domain_extract.convertToOrmObjects(filteredShodanJson1)

        self.assertDictEqual(filteredShodanJson1WithObjects, jsonWithOrmObjects)

def setUpDatabase(postgres):
    postgres.start()
    query_manager.createTables()


def tearDownDatabase(postgres):
    postgres.stop()

withTestDatabase = createFixture(setUpDatabase, tearDownDatabase)

class testDataInsertion(unittest.TestCase):
    postgresContainer = PostgresContainer("postgres:latest")

    def getDBEngineStub(postgresContainer):
        def _():
            return create_engine(postgresContainer.get_connection_url())
        return _
    
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withTestDatabase(postgres=postgresContainer)
    def test_insertDataFromObject_tablesNotFilled(self, mockCreateEngine):
        """
            Given a database with the tables specified in the model created, and no rows.
            When getOrCreate is called.
            Then the data is correctly inserted.
        """

        domain_extract.insertDataFromObject(deepcopy(filteredShodanJson1WithObjects))

        assertInsertionPerformedCorrectly(self)

    def withSomeColumnsSetUp():
        host1 = md.Host(address='8.8.8.8')
        query_manager.insert(host1)
        mainDomain1 = md.MainDomain(name='somedomain.org')
        query_manager.insert(mainDomain1)
        domainInfo1 = md.DomainInfo(domain='', subdomain=False, main_domain_id=1)
        query_manager.insert(domainInfo1)
        domainInfo2 = md.DomainInfo(domain='someSubdomain.org', subdomain=True, main_domain_id=1)
        query_manager.insert(domainInfo2)

    withSomeColumnsInserted = createFixture(withSomeColumnsSetUp, None)

    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withTestDatabase(postgres=postgresContainer)
    @withSomeColumnsInserted()
    def test_insertDataFromObject_tablesFilled(self, mockCreateEngine):
        """
            Given a database with the tables specified in the model created, and some rows.
            When getOrCreate is called.
            Then the data is correctly inserted.
        """
        domain_extract.insertDataFromObject(deepcopy(filteredShodanJson1WithObjects))

        allObjectsMainDomain = query_manager.getAllFromClass(md.MainDomain)
        allObjectsDomainInfo = query_manager.getAllFromClass(md.DomainInfo)
        allObjectsMXRecords = query_manager.getAllFromClass(md.MXRecord)
        allObjectsTXTRecords = query_manager.getAllFromClass(md.TXTRecord)
        allObjectsHost = query_manager.getAllFromClass(md.Host)
        allObjectsARecords = query_manager.getAllFromClass(md.ARecord)

        self.assertEqual(len(allObjectsMainDomain), 2)
        self.assertEqual(allObjectsMainDomain[1], md.MainDomain(id=2, name='domain.org', organization_id=None))

        self.assertEqual(len(allObjectsDomainInfo), 6)
        self.assertEqual(allObjectsDomainInfo[2], md.DomainInfo(domain='', id=3, main_domain_id=2, subdomain=False))
        self.assertEqual(allObjectsDomainInfo[3], md.DomainInfo(domain='sub1', id=4, main_domain_id=2, subdomain=True))
        self.assertEqual(allObjectsDomainInfo[4], md.DomainInfo(domain='sub2', id=5, main_domain_id=2, subdomain=True))
        self.assertEqual(allObjectsDomainInfo[5], md.DomainInfo(domain='_dmarc', id=6, main_domain_id=2, subdomain=True))

        self.assertEqual(len(allObjectsMXRecords), 3)
        self.assertEqual(
            allObjectsMXRecords[0],
            md.MXRecord(domain='mail.domain.org', id=1, parent_domain_info_id=3, timestamp=datetime(1991, 5, 23, 15, 17, 24)),  
        )
        self.assertEqual(
            allObjectsMXRecords[1],
            md.MXRecord(domain='mail2.domain.org', id=2, parent_domain_info_id=3, timestamp=datetime(1992, 5, 23, 15, 17, 24))
        )
        self.assertEqual(
            allObjectsMXRecords[2],
            md.MXRecord(domain='sub2.domain.org', id=3, parent_domain_info_id=5, timestamp=datetime(1996, 5, 23, 15, 17, 24))
        )

        self.assertEqual(len(allObjectsTXTRecords), 2)
        self.assertEqual(
            allObjectsTXTRecords[0],
            md.TXTRecord(content='v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all', id=1, parent_domain_info_id=3, timestamp=datetime(2023, 5, 23, 15, 11, 10))
        )
        self.assertEqual(
            allObjectsTXTRecords[1],
            md.TXTRecord(content='v=DMARC1; p=none', id=2, parent_domain_info_id=6, timestamp=datetime(1996, 5, 23, 15, 17, 24))
        )

        self.assertEqual(len(allObjectsHost), 4)
        self.assertEqual(
            allObjectsHost[1],
            md.Host(address='192.168.1.1')
        )
        self.assertEqual(
            allObjectsHost[2],
            md.Host(address='172.132.16.77')
        )
        self.assertEqual(
            allObjectsHost[3],
            md.Host(address='192.0.0.1')
        )

        self.assertEqual(len(allObjectsARecords), 3)
        self.assertEqual(
            allObjectsARecords[0],
            md.ARecord(id=1, ip_address='192.168.1.1', parent_domain_info_id=3, timestamp=datetime(1991, 5, 17, 7, 53, 21)),
        )
        self.assertEqual(
            allObjectsARecords[1],
            md.ARecord(id=2, ip_address='172.132.16.77', parent_domain_info_id=3, timestamp=datetime(2011, 5, 17, 1, 26, 37))
        )
        self.assertEqual(
            allObjectsARecords[2],
            md.ARecord(id=3, ip_address='192.0.0.1', parent_domain_info_id=4, timestamp=datetime(1996, 5, 23, 15, 17, 24))
        )
def assertInsertionPerformedCorrectly(self):
    allObjectsMainDomain = query_manager.getAllFromClass(md.MainDomain)
    allObjectsDomainInfo = query_manager.getAllFromClass(md.DomainInfo)
    allObjectsMXRecords = query_manager.getAllFromClass(md.MXRecord)
    allObjectsTXTRecords = query_manager.getAllFromClass(md.TXTRecord)
    allObjectsHost = query_manager.getAllFromClass(md.Host)
    allObjectsARecords = query_manager.getAllFromClass(md.ARecord)

    self.assertEqual(len(allObjectsMainDomain), 1)
    self.assertEqual(allObjectsMainDomain[0], md.MainDomain(id=1, name='domain.org', organization_id=None))

    self.assertEqual(len(allObjectsDomainInfo), 4)
    self.assertEqual(allObjectsDomainInfo[0], md.DomainInfo(domain='', id=1, main_domain_id=1, subdomain=False))
    self.assertEqual(allObjectsDomainInfo[1], md.DomainInfo(domain='sub1', id=2, main_domain_id=1, subdomain=True))
    self.assertEqual(allObjectsDomainInfo[2], md.DomainInfo(domain='sub2', id=3, main_domain_id=1, subdomain=True))
    self.assertEqual(allObjectsDomainInfo[3], md.DomainInfo(domain='_dmarc', id=4, main_domain_id=1, subdomain=True))

    self.assertEqual(len(allObjectsMXRecords), 3)
    self.assertEqual(
        allObjectsMXRecords[0],
        md.MXRecord(domain='mail.domain.org', id=1, parent_domain_info_id=1, timestamp=datetime(1991, 5, 23, 15, 17, 24)),  
    )
    self.assertEqual(
        allObjectsMXRecords[1],
        md.MXRecord(domain='mail2.domain.org', id=2, parent_domain_info_id=1, timestamp=datetime(1992, 5, 23, 15, 17, 24))
    )
    self.assertEqual(
        allObjectsMXRecords[2],
        md.MXRecord(domain='sub2.domain.org', id=3, parent_domain_info_id=3, timestamp=datetime(1996, 5, 23, 15, 17, 24))
    )

    self.assertEqual(len(allObjectsTXTRecords), 2)
    self.assertEqual(
        allObjectsTXTRecords[0],
        md.TXTRecord(content='v=spf1 a mx ip4:144.91.118.158 ip4:206.212.100.31 ~all', id=1, parent_domain_info_id=1, timestamp=datetime(2023, 5, 23, 15, 11, 10))
    )
    self.assertEqual(
        allObjectsTXTRecords[1],
        md.TXTRecord(content='v=DMARC1; p=none', id=2, parent_domain_info_id=4, timestamp=datetime(1996, 5, 23, 15, 17, 24))
    )

    self.assertEqual(len(allObjectsHost), 3)
    self.assertEqual(
        allObjectsHost[0],
        md.Host(address='192.168.1.1')
    )
    self.assertEqual(
        allObjectsHost[1],
        md.Host(address='172.132.16.77')
    )
    self.assertEqual(
        allObjectsHost[2],
        md.Host(address='192.0.0.1')
    )

    self.assertEqual(len(allObjectsARecords), 3)
    self.assertEqual(
        allObjectsARecords[0],
        md.ARecord(id=1, ip_address='192.168.1.1', parent_domain_info_id=1, timestamp=datetime(1991, 5, 17, 7, 53, 21)),
    )
    self.assertEqual(
        allObjectsARecords[1],
        md.ARecord(id=2, ip_address='172.132.16.77', parent_domain_info_id=1, timestamp=datetime(2011, 5, 17, 1, 26, 37))
    )
    self.assertEqual(
        allObjectsARecords[2],
        md.ARecord(id=3, ip_address='192.0.0.1', parent_domain_info_id=2, timestamp=datetime(1996, 5, 23, 15, 17, 24))
    )
if __name__ == '__main__':
     unittest.main()