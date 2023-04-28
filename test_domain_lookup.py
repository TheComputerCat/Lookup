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
        
        _ = domain_lookup.getShodanInfoFrom("example.com")

        mockFile.assert_called_once_with("shodan_api_key")
        shodan.Shodan.assert_called_with("798djfhj2208FFFEEDC4")

    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_shodan_domain_lookup(self, _):
        shodan.Shodan = MagicMock()
        shodan.Shodan().dns.domain_info = MagicMock()
        
        _ = domain_lookup.getShodanInfoFrom("example.com")
        
        shodan.Shodan().dns.domain_info.assert_called_once_with(
            domain="example.com",
            history=False,
            type=None,
            page=1
        )

    # continue with: def test_saver(self):
        

if __name__ == "__main__":
     unittest.main()

'''
domain-file 
Shodan API
domain-data-file

from unittest.mock import patch, mock_open
with patch("builtins.open", mock_open(read_data="data")) as mock_file:
    assert open("path/to/open").read() == "data"
mock_file.assert_called_with("path/to/open")

shdn.Shodan.assert_called_once_with()


api = Shodan('77sVOGfVkNmZuvO6ZtoIFlgWJI1eEhDV')
print(api.dns.domain_info(domain='google.com', history=False, type=None, page=1))
'''
