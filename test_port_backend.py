import unittest
from unittest.mock import patch, MagicMock
from port_backend import PortScanner
import logging
from rich.console import Console
from rich.markup import escape

console = Console()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.target = '127.0.0.1'
        self.scanner = PortScanner(self.target)
        logger.info(f"Setting up PortScanner with target {self.target}")

    def test_parse_ports_single(self):
        logger.info("Testing single port parsing")
        ports = self.scanner.parse_ports('80')
        self.assertEqual(ports, [80])
        logger.info("Single port parsing successful")

    def test_parse_ports_range(self):
        logger.info("Testing port range parsing")
        ports = self.scanner.parse_ports('20-25')
        self.assertEqual(list(ports), list(range(20, 26)))  # Convert range to list for comparison
        logger.info("Port range parsing successful")

    @patch('port_backend.socket.socket')
    def test_scan_port_open(self, mock_socket):
        logger.info("Testing open port scanning")
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.return_value = 0
        
        with patch('port_backend.SERVICE_VERSIONS', {80: 'HTTP'}):
            self.scanner.scan_port(80)
            mock_socket_instance.connect_ex.assert_called_with(('127.0.0.1', 80))
        logger.info("Open port scanning successful")

    @patch('port_backend.socket.socket')
    def test_scan_port_closed(self, mock_socket):
        logger.info("Testing closed port scanning")
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.return_value = 1
        
        self.scanner.scan_port(80)
        mock_socket_instance.connect_ex.assert_called_with(('127.0.0.1', 80))
        logger.info("Closed port scanning successful")

if __name__ == '__main__':
    result = unittest.TextTestRunner().run(unittest.makeSuite(TestPortScanner))
    if result.wasSuccessful():
        console.print(f"[green]✔ All tests passed successfully![/green]")
    else:
        console.print(f"[red]✘ Some tests failed. Please check the logs.[/red]")
