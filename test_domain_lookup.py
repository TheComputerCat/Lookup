import unittest
import domain_lookup
import shodan
import os

from unittest.mock import (
    patch,
    MagicMock,
    mock_open,
)

class Test(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_take_shodan_api_key(self, mockFile):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock()
        
        _ = domain_lookup.getShodanInfoOf("example.com")

        mockFile.assert_called_once_with("shodan_api_key")
        shodan.Shodan.assert_called_with("798djfhj2208FFFEEDC4")

    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_shodan_domain_lookup(self, _):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock()
        
        _ = domain_lookup.getShodanInfoOf("example.com")
        
        shodan.Shodan().dns.domain_info.assert_called_once_with(
            domain="example.com",
            history=False,
            type=None,
            page=1
        )
        
    @patch("builtins.open", new_callable=mock_open, read_data="dominio1")
    def test_read_file_single(self, mockFile):
        
        domainList = domain_lookup.getDomainsFromFile()

        self.assertEqual(domainList, ["dominio1"])
        mockFile.assert_called_once_with("./data/domain_list","r")

    @patch("builtins.open", new_callable=mock_open, read_data="dominio1,dominio2,dominio3")
    def test_read_file_many(self, mockFile):
        
        domainList = domain_lookup.getDomainsFromFile()

        self.assertEqual(domainList, ["dominio1","dominio2","dominio3"])
        mockFile.assert_called_once_with("./data/domain_list","r")

    @patch("domain_lookup.getShodanInfoOf", return_value="\{ip : 123456\}")
    def test_save_domain_info(self, mockGetInfo):

        domainName = "dominio1"
        targetDirectory = "./data/domain_raw_data/"
        relativePathOfNewFile = targetDirectory+domainName+".txt"
        domain_lookup.saveDomainInfo(domainName)

        numberOfFilesCreated = len(os.listdir(targetDirectory))

        self.assertGreater(numberOfFilesCreated,0)

        os.remove(relativePathOfNewFile)
    
            
        mockGetInfo.assert_called_once_with(
            domainName
        )

if __name__ == "__main__":
     unittest.main()
