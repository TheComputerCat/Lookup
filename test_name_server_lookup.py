import subprocess
import unittest
import name_server_lookup
import os
from unittest.mock import (
    patch,
    call,
    PropertyMock,
    MagicMock,
)

host0NslookupOutput = '0.0.0.0.in-addr.arpa\tname =my.name.Authoritative answers can be found from:\n\n'
host1NslookupOutput = '1.1.1.1.in-addr.arpa\tname =your.lastname.Authoritative answers can be found from:\n\n'


class nameServerLookupTest(unittest.TestCase):
    def test_parse_nslookup_output_case1(self):
        domain = 'my.name.'
        parseResult = name_server_lookup.parseNameServerLookupOutput(host0NslookupOutput)
        self.assertEqual(parseResult, domain)

    def test_parse_nslookup_output_case2(self):
        domain = 'your.lastname.'
        parseResult = name_server_lookup.parseNameServerLookupOutput(host1NslookupOutput)
        self.assertEqual(parseResult, domain)

    def test_get_file(self):
        '''
            Given a CSV file with a single column with domain names,
            when getRowsFromCSV is called with the path of that file,
            it should return a list with all the domains in the column.
        '''
        hostFilePath = './data/hosts'
        hostsFile = open(hostFilePath, 'w')
        hostsFile.write('host\n0.0.0.0\n1.1.1.1')
        hostsFile.close()

        res = name_server_lookup.getHostListFromPath(hostFilePath)

        os.remove(hostFilePath)

        self.assertEqual(res, ["0.0.0.0", "1.1.1.1"])

    @patch("subprocess.run")
    def test_nslookup_is_being_run_correctly_for_host(self, mockRun):
        '''
            Given a CSV with a single column with host directions
            When doNsLookupToListOfIp is called with the path to that file
            It should run nslookup command on each host
        '''

        hostFilePath = './data/hosts'
        hostsFile = open(hostFilePath, 'w')
        hostsFile.write('host\n0.0.0.0\n1.1.1.1')
        hostsFile.close()
        saveDirectoryPath = './data'

        type(mockRun.return_value).stdout = PropertyMock(return_value=host0NslookupOutput)
        domainPath = name_server_lookup.doNsLookupToListOfHosts(hostFilePath, saveDirectoryPath)

        os.remove(hostFilePath)
        os.remove(domainPath)

        mockRun.assert_has_calls([
            call(['nslookup', '0.0.0.0'], stdout=-1),
        ])
        mockRun.assert_has_calls([
            call(['nslookup', '1.1.1.1'], stdout=-1),
        ])

    @patch("subprocess.run")
    def test_domains_are_saved_in_a_file(self, mockRun):
        '''
            Given a CSV with a single column with host directions
            When doNsLookupToListOfIp is called with the path to that file
            It should ?
        '''
        hostFilePath = './data/hosts'
        hostsFile = open(hostFilePath, 'w')
        hostsFile.write('host\n0.0.0.0\n1.1.1.1')
        hostsFile.close()
        saveDirectoryPath = './data'

        type(mockRun.return_value).stdout = PropertyMock(side_effect=[host0NslookupOutput, host1NslookupOutput])
        domainsPath = name_server_lookup.doNsLookupToListOfHosts(hostFilePath, saveDirectoryPath)

        domainsFile = open(domainsPath, 'r')
        self.assertEqual(domainsFile.read(), host0NslookupOutput+host1NslookupOutput)
        domainsFile.close()
        os.remove(hostFilePath)
        os.remove(domainsPath)



if __name__ == '__main__':
    unittest.main()
