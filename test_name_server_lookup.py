import unittest
import name_server_lookup

class rDNS(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
