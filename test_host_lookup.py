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


if __name__ == "__main__":
    unittest.main()