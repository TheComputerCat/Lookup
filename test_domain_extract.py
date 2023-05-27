import unittest
import domain_extract
import json

from unittest.mock import (
    patch,
    Mock,
)

from domain_extract_fixtures import (
    jsonDic1,
    jsonDic2,
    jsonDataDic1,
    jsonDataDic2,
    jsonDataDicJoined
)

from common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestGetJson(unittest.TestCase):
    pathFile = './data/domain_raw_data/file1'
    @withATextFile(pathToTextFile=pathFile, content='{"someKey": "someValue"}')
    @patch('shodan_data_extract.open', new_callable=Mock, wraps=open)
    def test_getJsonFromFile_withAExistingFile(self, spyOpen, content):
        """
            Read json from file path
        """
        jsonResponse = domain_extract.getJsonFromFile(self.pathFile)

        spyOpen.assert_called_once_with(self.pathFile, 'r')
        self.assertDictEqual(jsonResponse, json.loads(content))
    
    def test_getJsonFromFile_withAExistingFile(self):
        """
            Read json from nonexisting path
        """
        jsonResponse =domain_extract.getJsonFromFile(self.pathFile)
        self.assertDictEqual(jsonResponse, {})

class TestGetData(unittest.TestCase):
    jsonDicList = [jsonDic1, jsonDic2]
    jsonDataDicList = jsonDataDicJoined

    def test_filterDataFomJson_withAExistingFile(self):
        """
            Get Data from a json dictionary from shodan
        """
        jsonResponse = domain_extract.filterJson(jsonDic1)

        self.maxDiff = None

        self.assertDictEqual(jsonResponse, jsonDataDic1)
    
    def test_filterJsonList_withAnArrayOfJson(self):
        """
            Get array of filtered data from a array of JSON
        """

        jsonRepose = domain_extract.filterFromJsonList(self.jsonDicList)

        self.maxDiff = None

        self.assertDictEqual(jsonRepose, jsonDataDicJoined)


class TestExtractDataFromFolder(unittest.TestCase):
    pathFile1 = './data/domain_raw_data/file1'

    jsonInFile1 = f'[{json.dumps(jsonDic1)},{json.dumps(jsonDic2)}]'
    jsonFilteredDataFile1 = jsonDataDicJoined

    @withATextFile(pathToTextFile=pathFile1, content=jsonInFile1)
    def test_extractDataFromFile_fromAFile(self, pathToTextFile):
        """
            From a file containing a shodan response, an array of two json, 
            extractDataFromFile returns an array of the filtered data from each
            json.
        """

        jsonReposesList = domain_extract.extractDataFromFile(pathToTextFile)

        self.maxDiff = None

        self.assertDictEqual(jsonReposesList, jsonDataDicJoined)

    pathFile2 = './data/domain_raw_data/file2'
    pathFile3 = './data/domain_raw_data/file3'

    jsonInFile2 = f'[{json.dumps(jsonDic1)},{json.dumps(jsonDic2)}]'
    jsonInFile3 = f'[{json.dumps(jsonDic2)}]'

    filteredDataInFolder = [jsonDataDicJoined, jsonDataDic2]

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