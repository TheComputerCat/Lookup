import unittest
import domain_lookup
import shodan
import os
import json

from unittest.mock import (
    patch,
    MagicMock,
    mock_open,
)

class Test(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_take_shodan_api_key(self, mockFile):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock(return_value={'more':False, 'ip': 12345})
        
        _ = domain_lookup.getShodanInfoOf("example.com")

        mockFile.assert_called_once_with("shodan_api_key")
        shodan.Shodan.assert_called_with("798djfhj2208FFFEEDC4")

    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_shodan_domain_lookup_single_page(self, _):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock(return_value={'more':False, 'ip': 12345})
        
        infoOptained = domain_lookup.getShodanInfoOf("example.com")
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
        
        infoOptained = domain_lookup.getShodanInfoOf("example.com")
        self.assertEqual(infoOptained,json.dumps([{'more':True, 'ip': 12345},{'more':False, 'ip': 12345}]))

        
        shodan.Shodan().dns.domain_info.assert_called_with(
            domain="example.com",
            history=False,
            type=None,
            page=2
        )

        
    @patch("builtins.open", new_callable=mock_open, read_data="dominio1")
    def test_get_domain_single(self, mockFile):
        
        domainList = domain_lookup.getDomainsList()

        self.assertEqual(domainList, ["dominio1"])
        mockFile.assert_called_once_with("./data/domain_list","r")

    @patch("builtins.open", new_callable=mock_open, read_data="dominio1,dominio2,dominio3")
    def test_get_domain_many(self, mockFile):
        
        domainList = domain_lookup.getDomainsList()

        self.assertEqual(domainList, ["dominio1","dominio2","dominio3"])
        mockFile.assert_called_once_with("./data/domain_list","r")

    @patch("domain_lookup.getShodanInfoOf", return_value="\{ip : 123456\}")
    def test_save_domain_info(self, mockGetInfo):
        domainName = "dominio1"
        targetDirectory = "./data/domain_raw_data/"
        relativePathOfNewFile = targetDirectory+domainName

        domain_lookup.saveDomainInfo(domainName)

        numberOfFilesCreated = len(os.listdir(targetDirectory))
        self.assertGreater(numberOfFilesCreated,0)

        os.remove(relativePathOfNewFile)
    
        mockGetInfo.assert_called_once_with(
            domainName
        )

    @patch('time.sleep', return_value=None)
    @patch("domain_lookup.getShodanInfoOf", return_value= 'domain.data')
    @patch("domain_lookup.getDomainsList",return_value = ["dominio1"])
    def test_get_all_data_single(self, mockGetDomains,mockGetInfo,sleep):
        domain_lookup.getAllRawData()

        targetDirectory = "./data/domain_raw_data/"
        numberOfFilesCreated = len(os.listdir(targetDirectory))
        self.assertGreater(numberOfFilesCreated,0)

        mockGetDomains.assert_called_once()
        mockGetInfo.assert_called_once_with("dominio1")
        sleep.assert_called_once()

    @patch('time.sleep', return_value=None)
    @patch("domain_lookup.getShodanInfoOf", side_effect= ['domain1.data','domain2.data','domain3.data'])
    @patch("domain_lookup.getDomainsList",return_value = ["dominio1","dominio2","dominio3"])
    def test_get_all_data_many(self, mockGetDomains,mockGetInfo,sleep):
        domain_lookup.getAllRawData()

        targetDirectory = "./data/domain_raw_data/"
        numberOfFilesCreated = len(os.listdir(targetDirectory))
        self.assertGreater(numberOfFilesCreated,2)

        mockGetDomains.assert_called_once()
        self.assertEqual(mockGetInfo.call_count,3)
        self.assertEqual(sleep.call_count,3)

    
    @patch("builtins.open", new_callable=mock_open, 
        read_data=json.dumps([
            {'more':False, 
             'data': [
                {
                    "subdomain": "*.auth.corp",
                    "type": "CNAME",
                    "value": "uberproxy.l.google.com",
                    "last_seen": "2021-01-26T13:04:34.018114+00:00"
                },
                {
                    "subdomain": "*.cloud.sandbox",
                    "type": "A",
                    "value": "74.125.142.81",
                    "last_seen": "2021-01-15T12:57:18.133727+00:00"
                }
                ]
            }
        ])
    )
    def test_get_domain_single_ip(self, domainInfo):
        
        domainIp = domain_lookup.getDomainIp('dominio1')

        self.assertEqual(domainIp, "74.125.142.81")

if __name__ == "__main__":
     unittest.main()
