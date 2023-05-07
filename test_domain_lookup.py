import unittest
import domain_lookup
import shodan
import os
import time

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
        self.assertEqual(infoOptained,str([{'more':False, 'ip': 12345}]))

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
        self.assertEqual(infoOptained,str([{'more':True, 'ip': 12345},{'more':False, 'ip': 12345}]))

        
        shodan.Shodan().dns.domain_info.assert_called_with(
            domain="example.com",
            history=False,
            type=None,
            page=2
        )

        
    @patch("builtins.open", new_callable=mock_open, read_data="dominio1")
    def test_read_file_single(self, mockFile):
        
        domainList = domain_lookup.getDomainsList()

        self.assertEqual(domainList, ["dominio1"])
        mockFile.assert_called_once_with("./data/domain_list","r")

    @patch("builtins.open", new_callable=mock_open, read_data="dominio1,dominio2,dominio3")
    def test_read_file_many(self, mockFile):
        
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

        mockGetDomains.assert_called_once_with()
        mockGetInfo.assert_called_once_with("dominio1")
        self.assertGreaterEqual(sleep.call_count,1)
if __name__ == "__main__":
     unittest.main()
