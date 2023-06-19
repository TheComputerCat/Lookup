import src.lookup.host_lookup as host_lookup
import unittest
import shodan
import time
from unittest.mock import (
    patch,
    MagicMock,
    mock_open,
    Mock,
    call,
)

from src.common.common import (
    asHexString,
)

class Test(unittest.TestCase):
    @patch("src.lookup.host_lookup.getTimeString", new_callable=Mock(return_value=lambda:""))
    @patch("subprocess.run")
    def test_call_nmap_command_with_ipv4(self, runMock, _):
        generator = host_lookup.getNmapInfoOf("8.8.8.8", "./data/host_nmap_data/")
        next(generator)
        next(generator)


        TCPcommand = ["nmap", "-sTV", "-top-ports", "2000", "--version-light", "-vv", "-oX",
                     "./data/host_nmap_data/{}-tcp".format(asHexString("8.8.8.8")), "8.8.8.8"]
        UDPcommand = ["nmap", "-sUV", "-top-ports", "200", "--version-light", "-vv", "-oX",
                     "./data/host_nmap_data/{}-udp".format(asHexString("8.8.8.8")), "8.8.8.8"]

        runMock.assert_has_calls([
            call(TCPcommand, capture_output=True, text=True), 
            call(UDPcommand, capture_output=True, text=True), 
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="")
    def test_read_empty_ip_list_file(self, mockFile):
        addresses = host_lookup.getAddressListFromFile('./data/ip_list')

        self.assertEqual(addresses, [])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8")
    def test_read_ip_list_file_with_one_address(self, mockFile):
        addresses = host_lookup.getAddressListFromFile('./data/ip_list')

        self.assertEqual(addresses, ["8.8.8.8"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n1.1.1.1")
    def test_read_ip_list_file_with_two_addresses(self, mockFile):
        addresses = host_lookup.getAddressListFromFile('./data/ip_list')

        self.assertEqual(addresses, ["8.8.8.8", "1.1.1.1"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n\n1.1.1.1")
    def test_read_ip_list_file_with_two_address_and_multiple_newlines(self, mockFile):
        addresses = host_lookup.getAddressListFromFile('./data/ip_list')

        self.assertEqual(addresses, ["8.8.8.8", "1.1.1.1"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="\n8.8.8.8\n\n1.1.1.1\n")
    def test_read_ip_list_file_with_more_newlines(self, mockFile):
        addresses = host_lookup.getAddressListFromFile('./data/ip_list')

        self.assertEqual(addresses, ["8.8.8.8", "1.1.1.1"])
        mockFile.assert_called_once_with("./data/ip_list", "r")
    
    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n8.8.8.8")
    def test_read_ip_list_file_with_one_address_repeated(self, mockFile):
        addresses = host_lookup.getAddressListFromFile('./data/ip_list')

        self.assertEqual(addresses, ["8.8.8.8"])
        mockFile.assert_called_once_with("./data/ip_list", "r")

class saveShodanInfoOfTest(unittest.TestCase):
    time.sleep = MagicMock()

    @patch("builtins.open", new_callable=mock_open, read_data="  798djfhj2208FFFEEDC4\n")
    def test_create_an_api_instance(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "data/", "data/test_data/shodan_api_key")

        shodan.Shodan.assert_has_calls([call("798djfhj2208FFFEEDC4")])

    @patch("builtins.open", new_callable=mock_open)
    def test_read_the_ip_list(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "./data/ip_raw_data/", "data/test_data/shodan_api_key")

        self.assertEqual(mockFile.call_count, 2)
        mockFile.assert_has_calls([
            call("data/test_data/ip_list", "r"),
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n0.0.0.0")
    def test_query_each_ip(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "./data/ip_raw_data/", "data/test_data/shodan_api_key")

        shodan.Shodan.assert_has_calls([
            call().host('8.8.8.8'),
            call().host('0.0.0.0'),
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n0.0.0.0")
    @patch("src.lookup.host_lookup.getTimeString", new_callable=lambda: lambda: "")
    def test_open_ip_file_for_each_ip(self, _, mockFile):
        shodan.Shodan = Mock()


        host_lookup.saveShodanInfoOf("data/test_data/ip_list", "data/test_data/ip_raw_data/", "data/test_data/shodan_api_key")

        mockFile.assert_has_calls([
            call("data/test_data/ip_raw_data/382e382e382e38", 'w'),  
        ])
        mockFile.assert_has_calls([
            call("data/test_data/ip_raw_data/302e302e302e30",'w'),
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n0.0.0.0")
    @patch("src.lookup.host_lookup.getTimeString", new_callable=lambda: lambda: "")
    def test_open_ip_files_in_the_same_directory_as_ip_list_file(self, _, mockFile):
        shodan.Shodan = Mock()

        path = "hello/bye/"
        _ = host_lookup.saveShodanInfoOf(path+"ip_list", "hello/bye/ip_raw_data/", "data/test_data/shodan_api_key")

        mockFile.assert_has_calls([
            call(path+"ip_raw_data/302e302e302e30", 'w'),
        ])
        mockFile.assert_has_calls([
            call(path+"ip_raw_data/382e382e382e38", 'w'),
        ])

if __name__ == "__main__":
    unittest.main()
