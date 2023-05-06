import host_lookup
import unittest
import shodan
from unittest.mock import (
    patch,
    MagicMock,
    mock_open,
)

class Test(unittest.TestCase):
    @patch("subprocess.run")
    def test_call_nmap_command(self, runMock):
        host_lookup.getNmapInfoOf("8.8.8.8", False)

        command = ["nmap", "-sT", "-sU", "-verbose", "8.8.8.8"]
        runMock.assert_called_once_with(
            command,
            capture_output=True,
            text=True
        )
    

    @patch("builtins.open", new_callable=mock_open, read_data="")
    def test_read_empty_ip_list_file(self, mockFile):
        addresses = host_lookup.getAddressList()

        self.assertEqual(addresses, [])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8")
    def test_read_ip_list_file_with_one_address(self, mockFile):
        addresses = host_lookup.getAddressList()

        self.assertEqual(addresses, ["8.8.8.8"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n1.1.1.1")
    def test_read_ip_list_file_with_two_addresses(self, mockFile):
        addresses = host_lookup.getAddressList()

        self.assertEqual(addresses, ["8.8.8.8", "1.1.1.1"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n\n1.1.1.1")
    def test_read_ip_list_file_with_two_address_and_multiple_newlines(self, mockFile):
        addresses = host_lookup.getAddressList()

        self.assertEqual(addresses, ["8.8.8.8", "1.1.1.1"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="\n8.8.8.8\n\n1.1.1.1\n")
    def test_read_ip_list_file_with_more_newlines(self, mockFile):
        addresses = host_lookup.getAddressList()

        self.assertEqual(addresses, ["8.8.8.8", "1.1.1.1"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n8.8.8.8")
    def test_read_ip_list_file_with_one_address_repeated(self, mockFile):
        addresses = host_lookup.getAddressList()

        self.assertEqual(addresses, ["8.8.8.8"])
        mockFile.assert_called_once_with("./data/ip_list", "r")


if __name__ == "__main__":
    unittest.main()
