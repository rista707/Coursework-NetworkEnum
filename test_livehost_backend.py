import unittest
from unittest.mock import patch, MagicMock
import livehost
import logging
from rich.console import Console

console = Console()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestLiveHost(unittest.TestCase):
    def setUp(self):
        logger.info("Setting up TestLiveHost")

    @patch('livehost.srp')
    def test_scan_network_arp(self, mock_srp):
        logger.info("Testing ARP network scan")
        # Mock the responses for ARP scan
        mock_response = [(MagicMock(), MagicMock(psrc='192.168.1.2', hwsrc='00:11:22:33:44:55'))]
        mock_srp.return_value = (mock_response, None)

        expected_result = [{'ip': '192.168.1.2', 'mac': '00:11:22:33:44:55'}]
        result = livehost.scan_network_arp('192.168.1.0/24')

        self.assertEqual(result, expected_result)
        logger.info("ARP network scan successful")

    @patch('livehost.sr1')
    def test_scan_network_icmp(self, mock_sr1):
        logger.info("Testing ICMP network scan")
        # Mock the responses for ICMP scan
        mock_response = MagicMock()
        mock_sr1.side_effect = [mock_response if i == 1 else None for i in range(1, 255)]

        expected_result = [{'ip': '192.168.1.1', 'mac': 'N/A'}]
        result = livehost.scan_network_icmp('192.168.1.0/24')

        self.assertEqual(result, expected_result)
        logger.info("ICMP network scan successful")

if __name__ == '__main__':
    result = unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(TestLiveHost))
    if result.wasSuccessful():
        console.print(f"[green]✔ All tests passed successfully![/green]")
    else:
        console.print(f"[red]✘ Some tests failed. Please check the logs.[/red]")
