import unittest
import subprocess
import os

from common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile,
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestDomainLookup(unittest.TestCase):
    domainDataDirPath = './data/domain_raw_data'
    addressListFilePath = './data/ip_list'
    
    @withATextFile(pathToTextFile='./data/domains', content='domain\nunal.edu.co\ngnu.org', deleteFolder=False)
    def test_1_doDomainLookup(self):
        subprocess.run(['python3', 'domain_lookup.py',
                        'lookup', './data/domains',
                        self.domainDataDirPath, './shodan_api_key'])
    
    def test_2_getAddresses(self):
        subprocess.run(['python3', 'domain_lookup.py',
                        'get_addresses', self.addressListFilePath,
                        self.domainDataDirPath])

class TestHostLookup(unittest.TestCase):
    @withATextFile(pathToTextFile='./data/ip_tiny_list', content='8.8.8.8\n209.51.188.116', deleteFolder=False)
    def test_1_doShodan(self):
        subprocess.run(['python3', 'host_lookup.py',
                        'shodan', './data/ip_tiny_list',
                        './data/host_shodan_data', './shodan_api_key'])
    
    @withATextFile(pathToTextFile='./data/ip_tiny_list', content='8.8.8.8\n209.51.188.116', deleteFolder=False)
    def test_1_doNmap(self):
        subprocess.run(['sudo', 'python3', 'host_lookup.py',
                        'nmap', './data/ip_tiny_list',
                        './data/host_nmap_data'])

if __name__ == '__main__':
     unittest.main()
