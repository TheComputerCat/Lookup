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
    MagicMock,
    mock_open,
)

class TestGetDomainList(unittest.TestCase):
    def test_get_nonexistent_file(self):
        '''
            When getRowsFromCSV is called with a path of a nonexistent file,
            it should return an empty list.
        '''
        res = domain_lookup.getDomainListFromPath('./path/to/nothing')
    
        self.assertEqual(res, [])
    
    def test_get_file_good_format(self):
        '''
            Given a CSV file with a single column with domain names,
            when getRowsFromCSV is called with the path of that file,
            it should return a list with all the domains in the column.
        '''
        path = './data/domains'
        f = open(path, 'w')
        f.write('domain\ngoogle.com\nfacebook.com')
        f.close()

        res = domain_lookup.getDomainListFromPath(path)

        self.assertEqual(res, ["google.com", "facebook.com"])

        os.remove(path)

class Test(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_take_shodan_api_key(self, mockFile):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock(return_value={'more':False, 'ip': 12345})
        
        _ = domain_lookup.getShodanInfoOf("example.com", 'shodan_api_key')

        mockFile.assert_called_once_with('shodan_api_key', 'r')
        shodan.Shodan.assert_called_with("798djfhj2208FFFEEDC4")

    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_shodan_domain_lookup_single_page(self, _):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock(return_value={'more':False, 'ip': 12345})
        
        infoOptained = domain_lookup.getShodanInfoOf("example.com", 'shodan_api_key')
        self.assertEqual(infoOptained,json.dumps([{'more':False, 'ip': 12345}]))

        shodan.Shodan().dns.domain_info.assert_called_once_with(
            domain="example.com",
            history=False,
            type=None,
            page=1
        )

    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_shodan_domain_lookup_multiple_page(self,_):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock(side_effect=[{'more':True, 'ip': 12345},{'more':False, 'ip': 12345}])
        
        infoOptained = domain_lookup.getShodanInfoOf("example.com", 'shodan_api_key')
        self.assertEqual(infoOptained,json.dumps([{'more':True, 'ip': 12345},{'more':False, 'ip': 12345}]))

        
        shodan.Shodan().dns.domain_info.assert_called_with(
            domain="example.com",
            history=False,
            type=None,
            page=2
        )

    def test_get_domain_many(self):
        
        path = "./data/domains"
        f = open(path, "w")
        f.write("domain\ngoogle.com\nfacebook.com")
        f.close()

        res = domain_lookup.getDomainListFromPath(path)


        self.assertEqual(res, ["google.com","facebook.com"])

        os.remove(path)

    @patch("domain_lookup.getShodanInfoOf", return_value="\{ip : 123456\}")
    def test_save_domain_info(self, mockGetInfo):
        domainName = "dominio1"
        targetDirectory = "./data/domain_raw_data/"
        relativePathOfNewFile = targetDirectory+asHexString(domainName)

        domain_lookup.saveDomainInfo(domainName, targetDirectory, 'shodan_api_key')

        numberOfFilesCreated = len(os.listdir(targetDirectory))
        self.assertGreater(numberOfFilesCreated,0)

        os.remove(relativePathOfNewFile)
    
        mockGetInfo.assert_called_once_with(
            domainName,
            'shodan_api_key'
        )

    @patch('time.sleep', return_value=None)
    @patch("domain_lookup.getShodanInfoOf", return_value= 'domain.data')
    @patch("domain_lookup.getDomainListFromPath",return_value = ["dominio1"])
    def test_get_all_data_single(self, mockGetDomains,mockGetInfo,sleep):
        targetDirectory = "./data/domain_raw_data/"
        domain_lookup.saveShodanInfoFromDomainFile('./data/domain_list', targetDirectory, 'shodan_api_key')
        
        numberOfFilesCreated = len(os.listdir(targetDirectory))
        self.assertGreater(numberOfFilesCreated,0)

        mockGetDomains.assert_called_once()
        mockGetInfo.assert_called_once_with("dominio1", 'shodan_api_key')

    domains = ["dominio1","dominio2","dominio3"]
    domainInfo = ['domain1.data','domain2.data','domain3.data']
    @patch('time.sleep', return_value=None)
    @patch("domain_lookup.getShodanInfoOf", side_effect=domainInfo)
    @patch("domain_lookup.getDomainListFromPath",return_value = domains)
    def test_get_all_data_many(self, mockGetDomains,mockGetInfo,sleep):
        targetDirectory = "./data/domain_raw_data/"
        domain_lookup.saveShodanInfoFromDomainFile('./data/domain_list', targetDirectory,'shodan_api_key')
        
        numberOfFilesCreated = len(os.listdir(targetDirectory))
        self.assertEqual(numberOfFilesCreated, 3)

        mockGetDomains.assert_called_once()
        self.assertEqual(mockGetInfo.call_count,3)

        for domainName, domainInfo in zip(map(asHexString, self.domains), self.domainInfo):
            with open(targetDirectory+domainName, "r") as f:
                self.assertEqual(f.read(), domainInfo)
            os.remove(targetDirectory+domainName)
    
    @patch("builtins.open", new_callable=mock_open, 
        read_data=json.dumps([
            {'more':False, 
             'data': [
                {
                    "type": "CNAME",
                    "value": "uberproxy.l.google.com"
                },
                {
                    "type": "A",
                    "value": "74.125.142.81",
                }
                ]
            }
        ])
    )

    def test_get_domain_single_ip(self, _):
        
        domainIp = domain_lookup.getIPAddressesFromShodanInfo('./data/domain_raw_data/dominio1')

        self.assertEqual(domainIp, "74.125.142.81\n")
    
    @patch("builtins.open", new_callable=mock_open, 
        read_data=json.dumps([
            {'more':True, 
             'data': [
                {
                    "type": "A",
                    "value": "74.125.142.81",
                }
                ]
            },
            {'more':False, 
             'data': [
                {
                    "type": "AAAA",
                    "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                },
                 {
                    "type": "A",
                    "value": "74.125.142.83",
                }
                ]
            }
        ])
    )

    def test_get_domain_many_pages_ip(self, _):
        
        domainIp = domain_lookup.getIPAddressesFromShodanInfo('./data/domain_raw_data/dominio1')

        self.assertEqual(domainIp, "74.125.142.81\n74.125.142.83\n")

    # @patch("domain_lookup.getDomainListFromPath",return_value = ["dominio1","dominio2","dominio3"])
    # @patch("domain_lookup.getIPAddressesFromShodanInfo",side_effect = ["74.125.142.80\n74.125.142.81","74.125.142.82","74.125.142.83"])
    # def test_create_ipList(self,mockgetIPAddressesFromShodanInfo,mockGetDomains):

    #     domain_lookup.saveIpList('./data/ip_list', './data/domain_raw_data/')
        
    #     self.assertTrue(os.path.isfile('./data/ip_list'))
    #     with open("./data/ip_list", 'r') as ipListFile:
    #         ipList = ipListFile.read()
    #         ipListFile.close()
    #         self.assertEqual(ipList,'74.125.142.80\n74.125.142.81\n74.125.142.82\n74.125.142.83\n')
        
    #     os.remove('./data/ip_list')

    #     mockGetDomains.assert_called_once()
    #     self.assertEqual(mockgetIPAddressesFromShodanInfo.call_count,3)
    #     mockgetIPAddressesFromShodanInfo.assert_called()

if __name__ == "__main__":
     unittest.main()
