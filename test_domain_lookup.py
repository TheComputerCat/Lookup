from collections.abc import Callable
from typing import Any
import unittest
import domain_lookup
import shodan
import os
import json

from common import (
    asHexString,
)

from unittest.mock import (
    patch,
    call,
    Mock,
)

from common import (
    createFixture,
    writeStringToFile,
    setUpWithATextFile,
    tearDownWithATextFile,
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestGetDomainList(unittest.TestCase):
    def test_getDomainListFromPath_getUnexistentFile(self):
        """
            When getRowsFromCSV is called with a path of a nonexistent file,
            it should return an empty list.
        """
        res = domain_lookup.getDomainListFromPath('./path/to/nothing')
    
        self.assertEqual(res, [])

    @withATextFile(pathToTextFile='./data/domains', content='domain\ngoogle.com\nfacebook.com')
    def test_getDomainListFromPath_file_good_format(self, pathToTextFile):
        """
            Given a CSV file with a single column with domain names,
            when getRowsFromCSV is called with the path of that file,
            it should return a list with all the domains in the column.
        """
        res = domain_lookup.getDomainListFromPath(pathToTextFile)

        self.assertEqual(res, ["google.com", "facebook.com"])

class TestGetShodanInfoDomain(unittest.TestCase):
    @withATextFile(pathToTextFile='./shodan_api_key', content='798djfhj2208FFFEEDC4')
    @patch('shodan.Shodan', new_callable=Mock)
    def test_getShodanInfoOf_domainWithMultipleDataPages(self, shodanMock):
        """
            Given a domain, shodan API is called with correct credentials and
            response from shodan API with multiple pages is saved to JSON 
            correctly.
        """
        shodan.Shodan().dns.domain_info = Mock(side_effect=[{'more':True, 'ip': '168.176.196.13'},{'more':False, 'ip': '168.176.196.11'}])
        
        infoOptained = domain_lookup.getShodanInfoOf('example.com', 'shodan_api_key')

        shodan.Shodan.assert_called_with('798djfhj2208FFFEEDC4')

        shodan.Shodan().dns.domain_info.assert_has_calls([
            call(domain='example.com', history=False, type=None, page=1),
            call(domain='example.com', history=False, type=None, page=2)
        ])

        self.assertEqual(infoOptained,json.dumps([{'more':True, 'ip': '168.176.196.13'},{'more':False, 'ip': '168.176.196.11'}]))


class TestSaveDomainInfo(unittest.TestCase):
    domainName = 'domain1'
    targetDirectory = "./data/domain_raw_data/"

    @classmethod
    def tearDownClass(self):
        os.remove(f'{self.targetDirectory}{self.domainName}')
        os.removedirs(self.targetDirectory)
        
    @patch('domain_lookup.writeStringToFile', new_callable=Mock, wraps=writeStringToFile)
    @patch('domain_lookup.getShodanInfoOf', new_callable=Mock, return_value='{ip : 123456}')
    def test_saveDomainInfo(self, mockGetShodanInfoOf, spyWriteStringToFile):
        """
        Given a domain, the information from Shodan is saved 
        in a file.
        """
        domain_lookup.saveDomainInfo(self.domainName, self.targetDirectory, 'shodan_api_key')
    
        mockGetShodanInfoOf.assert_called_once_with(
            self.domainName,
            'shodan_api_key'
        )

        spyWriteStringToFile.assert_called_once_with(
            f'{self.targetDirectory}{self.domainName}',
            '{ip : 123456}',
            overwrite=True
        )

class TestSaveShodanInfoFromDomainFile(unittest.TestCase):
    domainsPathFile = './data/domain_list'
    domains = ["domain1","domain2","domain3"]
    domainsInfo = ['domain1.data','domain2.data','domain3.data']
    targetDirectory = "./data/domain_raw_data/"
    shodanAPIKeyPathFile = 'shodan_api_key'

    @classmethod
    def tearDownClass(self):
        for domainName in self.domains:
            os.remove(f'{self.targetDirectory}{domainName}')
        os.removedirs(self.targetDirectory)
    
    @patch('domain_lookup.saveDomainInfo', new_callable=Mock, wraps=domain_lookup.saveDomainInfo)
    @patch('domain_lookup.getShodanInfoOf', new_callable=Mock,side_effect=domainsInfo)
    @patch('domain_lookup.getDomainListFromPath', new_callable=Mock, return_value = domains)
    def test_saveShodanInfoFromDomainFile_multipleDomains(self, mockGetDomainListFromPath, mockGetShodanInfoOf, spySaveDomainInfo):
        """
        Given file with 3 different domains, saveShodanInfoFromDomainFile is called with this path, a target directory
        and the path to the API KEY. Then de information recollected by getShodanInfoOf is saved in files using
        saveDomainInfo
        """
        domain_lookup.saveShodanInfoFromDomainFile(self.domainsPathFile, self.targetDirectory, self.shodanAPIKeyPathFile)
        
        mockGetDomainListFromPath.assert_called_once_with(
            self.domainsPathFile
        )

        self.assertEqual(spySaveDomainInfo.call_count, 3)

        for domain in self.domains:
            with self.subTest(domain=domain):
                spySaveDomainInfo.assert_has_calls([call(domain, self.targetDirectory, self.shodanAPIKeyPathFile)])
    
class TestGetIPAddressesFromShodanInfo(unittest.TestCase):
    @withATextFile(pathToTextFile='./data/domain_raw_data/domain1', content=json.dumps([
            {
                'more':True, 
                'data': [{
                    'type': 'A',
                    'value': '74.125.142.81',
                }]
            },
            {
                'more':False, 
                'data': [{
                    'type': 'AAAA',
                    'value': '74.125.142.82',
                },
                {
                    'type': 'A',
                    'value': '74.125.142.83',
                }]
            }
        ])
    )
    def test_getIPAddressesFromShodanInfo_multiplePages(self, pathToTextFile):
        """
        Given a file with the data recollected from shodan, getIPAddressesFromShodanInfo 
        gets the ips from this data.
        """
        
        domainIp = domain_lookup.getIPAddressesFromShodanInfo('domain1', os.path.dirname(pathToTextFile) + '/')

        self.assertEqual(domainIp, '74.125.142.81\n74.125.142.82\n74.125.142.83\n')

class TestSaveIpList(unittest.TestCase):
    domainListPath = './data/domain_list'
    IPListFilePath = './data/ip_list'
    domains = ['domain1','domain2','domain3']

    @classmethod
    def tearDownClass(self):
        os.remove(self.IPListFilePath)
    
    @patch('domain_lookup.writeStringToFile', new_callable=Mock, wraps=writeStringToFile)
    @patch('domain_lookup.getDomainListFromPath', return_value=domains)
    @patch('domain_lookup.getIPAddressesFromShodanInfo', side_effect = ['74.125.142.80\n74.125.142.81','74.125.142.82','74.125.142.83'])
    def test_saveIpList(self, mockGetIPAddressesFromShodanInfo, mockGetDomainListFromPath, spyWriteStringToFile):

        domain_lookup.saveIpList(self.domainListPath, self.IPListFilePath)
        
        mockGetDomainListFromPath.assert_called_once_with(self.domainListPath)

        self.assertEqual(mockGetIPAddressesFromShodanInfo.call_count,3)

        for domain in self.domains:
            with self.subTest(domain=domain):
                mockGetIPAddressesFromShodanInfo.assert_has_calls([
                    call(domain)
                ])

        spyWriteStringToFile.assert_called_once_with(
            self.IPListFilePath,
            '74.125.142.80\n74.125.142.81\n74.125.142.82\n74.125.142.83\n',
            overwrite=True
        )

if __name__ == '__main__':
     unittest.main()
