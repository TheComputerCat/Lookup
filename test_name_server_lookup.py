import unittest
import name_server_lookup
import os
from unittest.mock import (
    patch,
    call,
)

class nameServerLookupTest(unittest.TestCase):
    def test_parse_nslookup_output_case1(self):
        commandReturn = '0.0.0.0.in-addr.arpa\tname =my.name.Authoritative answers can be found from:\n\n'
        domain = 'my.name.'
        parseResult = name_server_lookup.parseNameServerLookupOutput(commandReturn)
        self.assertEqual(parseResult, domain)

    def test_parse_nslookup_output_case2(self):
        commandReturn = '1.1.1.1.in-addr.arpa\tname =your.lastname.Authoritative answers can be found from:\n\n'
        domain = 'your.lastname.'
        parseResult = name_server_lookup.parseNameServerLookupOutput(commandReturn)
        self.assertEqual(parseResult, domain)

    def test_get_file(self):
        '''
            Given a CSV file with a single column with domain names,
            when getRowsFromCSV is called with the path of that file,
            it should return a list with all the domains in the column.
        '''
        path = './data/hosts'
        f = open(path, 'w')
        f.write('host\n0.0.0.0\n1.1.1.1')
        f.close()

        res = name_server_lookup.getHostListFromPath(path)

        self.assertEqual(res, ["0.0.0.0", "1.1.1.1"])

        os.remove(path)
    @patch("subprocess.run")
    def test_nslookup_is_being_run_correctly_for_host(self, mockRun):
        '''
            Given a CSV with a single column with host directions
            When doNsLookupToListOfIp is called with the path to that file
            It should run nslookup command on each host
        '''
        path = './data/hosts'
        f = open(path, 'w')
        f.write('host\n0.0.0.0\n1.1.1.1')
        f.close()

        res = name_server_lookup.doNsLookupToListOfHosts(path)

        os.remove(path)

        mockRun.assert_has_calls([
            call(['nslookup', '0.0.0.0'], stdout=-1),
            call(['nslookup', '1.1.1.1'], stdout=-1),
        ])

if __name__ == '__main__':
    unittest.main()
