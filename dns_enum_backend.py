import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import sublist3r
import socket
from whois import whois  # Ensure this is the correct library
import argparse
import sys

def enum_subdomains(domain, wordlist=None):
    try:
        if wordlist:
            subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=True, engines=None, wordlist=wordlist)
        else:
            subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return list(set(subdomains))
    except Exception as e:
        print(f"Error enumerating subdomains: {e}")
        return []

def enum_dns_records(domain):
    record_types = ['A', 'MX', 'TXT', 'DNSKEY', 'CNAME', 'NS', 'SOA']
    dns_records = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_records[rtype] = [str(rdata) for rdata in answers]
        except Exception as e:
            print(f"No {rtype} records found for {domain}: {e}")
    return dns_records

def reverse_dns_lookup(ip_address):
    try:
        addr = dns.reversename.from_address(ip_address)
        domain = str(dns.resolver.resolve(addr, 'PTR')[0])
        return domain
    except dns.resolver.NXDOMAIN:
        print(f"No PTR record found for IP address {ip_address}")
    except dns.resolver.Timeout:
        print(f"Timeout occurred while resolving the PTR record for IP address {ip_address}")
    except dns.resolver.NoAnswer:
        print(f"No answer was returned for the PTR query of IP address {ip_address}")
    except Exception as e:
        print(f"Reverse DNS lookup failed for {ip_address}: {e}")
    return None

def enum_srv_records(domain):
    services = {
        '_sip._tcp.': 'SIP',
        '_ldap._tcp.': 'LDAP',
        '_http._tcp.': 'HTTP',
        '_imap._tcp.': 'IMAP',
        '_smtp._tcp.': 'SMTP',
        '_xmpp-server._tcp.': 'XMPP Server',
        '_xmpp-client._tcp.': 'XMPP Client',
        '_ftp._tcp.': 'FTP',
        '_https._tcp.': 'HTTPS'
    }
    srv_records = {}
    for service, name in services.items():
        try:
            answers = dns.resolver.resolve(service + domain, 'SRV')
            srv_records[name] = [(str(rdata.target), rdata.port) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            print(f"No {name} SRV records found for {domain}")
    return srv_records

def zone_transfer(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            try:
                ns_address = dns.resolver.resolve(str(ns), 'A')[0].to_text()
                zone = dns.zone.from_xfr(dns.query.xfr(ns_address, domain))
                records = {str(name): [str(rdata) for rdata in rdatasets] for name, node in zone.nodes.items()}
                print(f"Zone transfer successful for {domain} from {ns}")
                return records
            except dns.query.TransferError:
                print(f"Zone transfer permission denied for {ns}")
            except dns.query.BadResponse:
                print(f"Bad response from {ns}")
            except dns.exception.FormError:
                print(f"Form error in response from {ns}")
            except Exception as e:
                print(f"An unexpected error occurred with {ns}: {e}")
    except Exception as e:
        print(f"Error resolving NS records for {domain}: {e}")
    return None

def whois_info(domain):
    try:
        info = whois(domain)
        return info
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        return None

def get_ip_address(domain_name):
    try:
        # Get the primary IP address associated with the hostname
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            print(f"Domain name '{domain_name}' does not exist: {e}")
        else:
            print(f"Network error while resolving IP address for {domain_name}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Domain Enumeration Tool", usage="%(prog)s [options] target_domain")
    parser.add_argument('-e', '--enum_subdomains', action='store_true', help="Enumerate subdomains")
    parser.add_argument('-ed', '--enum_dns', action='store_true', help="Enumerate DNS records")
    parser.add_argument('-r', '--reverse_dns', action='store_true', help="Perform reverse DNS lookup")
    parser.add_argument('-s', '--enum_srv', action='store_true', help="Enumerate SRV records")
    parser.add_argument('-z', '--zone_transfer', action='store_true', help="Attempt zone transfer")
    parser.add_argument('-w', '--whois', action='store_true', help="Retrieve WHOIS information")
    parser.add_argument('-wl', '--wordlist', help="Custom wordlist for subdomain enumeration")
    parser.add_argument('target', help="Target domain")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    domain = args.target
    
    if args.enum_subdomains:
        print("\nEnumerating subdomains:")
        subdomains = enum_subdomains(domain, args.wordlist)
        print(subdomains)
    
    if args.enum_dns:
        print("\nEnumerating DNS records:")
        dns_records = enum_dns_records(domain)
        for record_type, records in dns_records.items():
            print(f"{record_type}: {records}")

    if args.reverse_dns:
        print("\nPerforming reverse DNS lookup:")
        ip_address = get_ip_address(domain)
        if ip_address:
            reverse_domain = reverse_dns_lookup(ip_address)
            print(f"Reverse DNS lookup result: {reverse_domain}")
    
    if args.enum_srv:
        print("\nEnumerating SRV records:")
        srv_records = enum_srv_records(domain)
        for service, records in srv_records.items():
            print(f"{service} SRV records: {records}")
    
    if args.zone_transfer:
        print("\nAttempting zone transfer:")
        zone_records = zone_transfer(domain)
        if zone_records:
            for name, records in zone_records.items():
                print(f"{name}: {records}")
        else:
            print("Zone transfer unsuccessful.")
    
    if args.whois:
        print("\nRetrieving WHOIS information:")
        domain_info = whois_info(domain)
        if domain_info:
            print(domain_info)

if __name__ == "__main__":
    main()
