import unittest
from dns_enum_backend import (
    enum_subdomains,
    enum_dns_records,
    reverse_dns_lookup,
    enum_srv_records,
    zone_transfer,
    whois_info,
    get_ip_address,
)

class CustomTestResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.write('✔ ')
        self.stream.flush()

class CustomTestRunner(unittest.TextTestRunner):
    def _makeResult(self):
        return CustomTestResult(self.stream, self.descriptions, self.verbosity)

class TestDNSEnumBackend(unittest.TestCase):
    def setUp(self):
        self.test_domain = "schoolworkspro.com"
        self.test_ip = "202.51.82.178"
        self.invalid_domain = "invalid-domain.com"
        self.invalid_ip = "256.256.256.256"

    def test_enum_subdomains(self):
        result = enum_subdomains(self.test_domain)
        self.assertIsInstance(result, list)

    def test_enum_dns_records(self):
        result = enum_dns_records(self.test_domain)
        self.assertIsInstance(result, dict)
        # Check that the result is a dictionary, even if empty
        self.assertTrue(isinstance(result, dict), "DNS records result is not a dictionary")

    def test_reverse_dns_lookup(self):
        result = reverse_dns_lookup(self.test_ip)
        self.assertTrue(result is None or isinstance(result, str))

    def test_enum_srv_records(self):
        result = enum_srv_records(self.test_domain)
        self.assertIsInstance(result, dict)
        # Check that the result is a dictionary, even if empty
        self.assertTrue(isinstance(result, dict), "SRV records result is not a dictionary")

    def test_zone_transfer(self):
        result = zone_transfer(self.test_domain)
        self.assertTrue(result is None or isinstance(result, dict))

    def test_whois_info(self):
        result = whois_info(self.test_domain)
        self.assertIsInstance(result, dict)
        self.assertIn("domain_name", result)

    def test_get_ip_address(self):
        result = get_ip_address(self.test_domain)
        self.assertIsInstance(result, str)
        self.assertEqual(result, self.test_ip)

    # Testing invalid inputs
    def test_invalid_domain(self):
        result = get_ip_address(self.invalid_domain)
        self.assertIsNone(result)

    def test_invalid_ip_reverse_lookup(self):
        result = reverse_dns_lookup(self.invalid_ip)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main(testRunner=CustomTestRunner(verbosity=2))
