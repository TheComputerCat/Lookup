import unittest
import domain_extract
import json
from datetime import datetime

from unittest.mock import (
    patch,
    Mock,
)

from domain_extract_fixtures import (
    shodanJson1,
    shodanJson2,
    filteredShodanJson1,
    filteredShodanJson2,
    filteredJoinedShodanJson1AndJson2,
    filteredShodanJson1WithObjects
)

from common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

import model as md

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestGetJson(unittest.TestCase):
    filePath = './data/domain_raw_data/file1'
    @withATextFile(pathToTextFile=filePath, content='{"someKey": "someValue"}')
    @patch('domain_extract.open', new_callable=Mock, wraps=open)
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

        for i in range(0, 1):
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

    def test_asa_fromFilteredJsonCreateObjects(self):
        """
            When a filtered Json is given, a new json is returned
            with the data converted to the ORM objects.
        """

        self.maxDiff = None
        jsonWithOrmObjects = domain_extract.convertToOrmObjects(filteredShodanJson1)

        self.assertDictEqual(filteredShodanJson1WithObjects, jsonWithOrmObjects)
if __name__ == '__main__':
     unittest.main()