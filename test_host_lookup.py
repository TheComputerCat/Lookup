import host_lookup
import unittest
import shodan
from unittest.mock import (
    patch,
    MagicMock,
    mock_open,
    Mock,
    call,
)

class TestNmap(unittest.TestCase):
    @patch("subprocess.run")
    def test_call_nmap_command_with_ipv4(self, runMock):
        host_lookup.getNmapInfoOf("8.8.8.8", False)

        runMock.assert_has_calls([
            call(
                ["nmap", "-sSV", "-top-ports", "5000", "--version-light", "-vv", "-oX", "8.8.8.8"],
                capture_output=True,
                text=True
            ),
            call(
                ["nmap", "-sUV", "-top-ports", "200", "--version-light", "-vv", "-oX", "8.8.8.8"],
                capture_output=True,
                text=True
            ),
        ])
    
    @patch("subprocess.run")
    def test_call_nmap_command_with_ipv6(self, runMock):
        host_lookup.getNmapInfoOf("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True)

        runMock.assert_has_calls([
            call(
                ["nmap", "-sSV", "-top-ports", "5000", "--version-light", "-vv", "-oX", "-6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
                capture_output=True,
                text=True
            ),
            call(
                ["nmap", "-sUV", "-top-ports", "200", "--version-light", "-vv", "-oX", "-6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
                capture_output=True,
                text=True
            ),
        ])

class TestReadAddressList(unittest.TestCase):
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

class TestShodan(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="798djfhj2208FFFEEDC4")
    def test_saveShodanInfoOf_creates_an_api_instance(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "data/test_data/shodan_api_key")

        shodan.Shodan.assert_has_calls([call("798djfhj2208FFFEEDC4")])

    @patch("builtins.open", new_callable=mock_open)
    def test_saveShodanInfoOf_reads_the_ip_list(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "data/test_data/shodan_api_key")

        self.assertEqual(mockFile.call_count, 2)
        mockFile.assert_has_calls([
            call("data/test_data/ip_list", "r"),
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n0.0.0.0")
    def test_saveShodanInfoOf_queries_the_ip_list(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "data/test_data/shodan_api_key")

        shodan.Shodan.assert_has_calls([
            call().host('8.8.8.8'),
            call().host('0.0.0.0'),
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n0.0.0.0")
    def test_saveShodanInfoOf_opens_ip_file_for_each_ip(self, mockFile):
        shodan.Shodan = Mock()

        _ = host_lookup.saveShodanInfoOf("data/test_data/ip_list", "data/test_data/shodan_api_key")

        mockFile.assert_has_calls([
            call("data/test_data/ip_raw_data/0.0.0.0", 'w'),
        ])
        mockFile.assert_has_calls([
            call("data/test_data/ip_raw_data/8.8.8.8",'w'),
        ])

    @patch("builtins.open", new_callable=mock_open, read_data="8.8.8.8\n0.0.0.0")
    def test_saveShodanInfoOf_opens_ip_files_depending_on_IP_list_path(self, mockFile):
        shodan.Shodan = Mock()

        path = "hello/bye/"
        _ = host_lookup.saveShodanInfoOf(path+"ip_list", "data/test_data/shodan_api_key")

        mockFile.assert_has_calls([
            call(path+"ip_raw_data/0.0.0.0", 'w'),
        ])

if __name__ == "__main__":
    unittest.main()
