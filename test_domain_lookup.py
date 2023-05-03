import unittest
import domain_lookup
import shodan

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
    def test_read_file(self, mockFile):
        
        domainList = domain_lookup.getDomainsFromFile()

        self.assertEqual(domainList, ["dominio1"])
        mockFile.assert_called_once_with("./data/domain_list","r")


if __name__ == "__main__":
     unittest.main()
