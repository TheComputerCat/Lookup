import unittest
import domain_extract
import json

from unittest.mock import (
    patch,
    Mock,
)

from domain_extract_fixtures import (
    shodanJson1,
    shodanJson2,
    filteredShodanJson1,
    filteredShodanJson2,
    filteredJoinedShodanJson1AndJson2
)

from common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

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

if __name__ == '__main__':
     unittest.main()