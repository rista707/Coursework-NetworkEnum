import unittest
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# Importing all test modules
import test_dns_enum
import test_livehost_backend
import test_port_backend

# Function to display which test suite is running
def display_running_test(test_name):
    text = Text(test_name, justify="center", style="bold yellow")
    panel = Panel.fit(text, border_style="bold red", title="Running Tests", title_align="center")
    console.print(panel)

# Create a test suite combining all test cases
def suite():
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(test_dns_enum.TestDNSEnumBackend))
    test_suite.addTest(unittest.makeSuite(test_livehost_backend.TestLiveHost))
    test_suite.addTest(unittest.makeSuite(test_port_backend.TestPortScanner))
    return test_suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    
    # Running DNS Enum Tests
    display_running_test("DNS ENUM TESTING")
    result_dns = runner.run(unittest.makeSuite(test_dns_enum.TestDNSEnumBackend))

    # Running Live Host Tests
    display_running_test("LIVE HOST TESTING")
    result_livehost = runner.run(unittest.makeSuite(test_livehost_backend.TestLiveHost))

    # Running Port Scanner Tests
    display_running_test("PORT SCANNER TESTING")
    result_port = runner.run(unittest.makeSuite(test_port_backend.TestPortScanner))

    # Aggregate results
    all_successful = result_dns.wasSuccessful() and result_livehost.wasSuccessful() and result_port.wasSuccessful()
    
    if all_successful:
        console.print(f"[green bold]✔ All tests passed successfully![/green bold]")
    else:
        console.print(f"[red bold]✘ Some tests failed. Please check the logs.[/red bold]")
