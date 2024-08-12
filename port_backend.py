import argparse
import socket
import sys
import threading
from datetime import datetime
import pyfiglet
from termcolor import colored
from scapy.all import sr1, IP, ICMP, TCP

# Dictionary mapping well-known ports to their respective services (for demonstration)
SERVICE_VERSIONS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    161: "SNMP",
    443: "HTTPS",
    3306: "MySQL",
}

class PortScanner:
    def __init__(self, target, ports=None, os_detect=False, log_callback=None):
        self.target = target
        self.os_detect = os_detect
        self.log_callback = log_callback or print
        if ports:
            self.ports = self.parse_ports(ports)
        else:
            self.ports = range(1, 1001)  # Default to scanning first 1000 ports

    def parse_ports(self, port_arg):
        if '-' in port_arg:
            start, end = map(int, port_arg.split('-'))
            return range(start, end + 1)
        else:
            return [int(port_arg)]

    def scan(self):
        self.print_header("Port Scanner")
        self.log_callback("-" * 50)
        self.log_callback("Scanning Target: " + self.target)
        self.log_callback("Scanning started at: " + str(datetime.now()))
        self.log_callback("-" * 50)

        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Perform OS detection if enabled
        if self.os_detect:
            self.os_detection()

    def scan_port(self, port_num):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((self.target, port_num))
            if result == 0:
                service = SERVICE_VERSIONS.get(port_num, "Unknown Service")
                self.log_callback(f"Port {port_num}/tcp open   {service}")
                if service == "SSH":
                    self.detect_ssh_version(s, port_num)
                elif service == "HTTP":
                    self.detect_http_version(s, port_num)
                elif service == "FTP":
                    self.detect_ftp_version(s, port_num)
                elif service == "Telnet":
                    self.detect_telnet_version(s, port_num)
                elif service == "SMTP":
                    self.detect_smtp_version(s, port_num)
                elif service == "DNS":
                    self.detect_dns_version(s, port_num)
                elif service == "POP3":
                    self.detect_pop3_version(s, port_num)
                elif service == "NTP":
                    self.detect_ntp_version(s, port_num)
                elif service == "SNMP":
                    self.detect_snmp_version(s, port_num)
                elif service == "HTTPS":
                    self.detect_https_version(s, port_num)
                elif service == "MySQL":
                    self.detect_mysql_version(s, port_num)
                else:
                    self.log_callback(f"Port {port_num}/tcp open   {service} - Version Detection Not Implemented")
            s.close()
        except KeyboardInterrupt:
            self.log_callback("\n Exiting Program !!")
            sys.exit()
        except socket.gaierror:
            self.log_callback("\n Hostname could not be resolved !!")
            sys.exit()
        except socket.error:
            self.log_callback("\n Server not responding !!")
            sys.exit()

    def detect_ssh_version(self, sock, port_num):
        try:
            sock.send(b"SSH-2.0\r\n")
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   SSH - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   SSH - Version Detection Error: {str(e)}")

    def detect_http_version(self, sock, port_num):
        try:
            sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = sock.recv(1024).decode('utf-8').strip()
            headers = response.split('\r\n\r\n')[0]
            server_header = [line for line in headers.split('\r\n') if line.startswith('Server')]
            if server_header:
                server_version = server_header[0].split(': ')[1]
                self.log_callback(f"Port {port_num}/tcp open   HTTP - Version: {server_version}")
            else:
                self.log_callback(f"Port {port_num}/tcp open   HTTP - Version: Unknown")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   HTTP - Version Detection Error: {str(e)}")

    def detect_ftp_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   FTP - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   FTP - Version Detection Error: {str(e)}")

    def detect_telnet_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   Telnet - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   Telnet - Version Detection Error: {str(e)}")

    def detect_smtp_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   SMTP - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   SMTP - Version Detection Error: {str(e)}")

    def detect_dns_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   DNS - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   DNS - Version Detection Error: {str(e)}")

    def detect_pop3_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   POP3 - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   POP3 - Version Detection Error: {str(e)}")

    def detect_ntp_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   NTP - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   NTP - Version Detection Error: {str(e)}")

    def detect_snmp_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   SNMP - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   SNMP - Version Detection Error: {str(e)}")

    def detect_https_version(self, sock, port_num):
        try:
            sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = sock.recv(1024).decode('utf-8').strip()
            headers = response.split('\r\n\r\n')[0]
            server_header = [line for line in headers.split('\r\n') if line.startswith('Server')]
            if server_header:
                server_version = server_header[0].split(': ')[1]
                self.log_callback(f"Port {port_num}/tcp open   HTTPS - Version: {server_version}")
            else:
                self.log_callback(f"Port {port_num}/tcp open   HTTPS - Version: Unknown")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   HTTPS - Version Detection Error: {str(e)}")

    def detect_mysql_version(self, sock, port_num):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            self.log_callback(f"Port {port_num}/tcp open   MySQL - Version: {banner}")
        except Exception as e:
            self.log_callback(f"Port {port_num}/tcp open   MySQL - Version Detection Error: {str(e)}")

    def os_detection(self):
        try:
            ip = IP(dst=self.target)
            icmp = ICMP()
            packet = ip/icmp
            response = sr1(packet, timeout=1, verbose=False)

            if response:
                ttl = response.ttl
                os_guess = self.guess_os(ttl)
                self.log_callback(f"OS Detection: {os_guess}")
            else:
                self.log_callback("OS Detection: Unable to detect OS")

        except Exception as e:
            self.log_callback(f"OS Detection Error: {str(e)}")

    def guess_os(self, ttl):
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Networking Device"
        else:
            return "Unknown OS"

    def print_header(self, text):
        ascii_banner = pyfiglet.figlet_format(text)
        colored_banner = colored(ascii_banner, color='red')
        self.log_callback(colored_banner)

def main():
    parser = argparse.ArgumentParser(description="Python3 Port Scanner")
    parser.add_argument('-t', metavar='TARGET', type=str, required=True, help='target IP address')
    parser.add_argument('-p', metavar='PORT', type=str, help='port or range of ports (e.g., 1-100)')
    parser.add_argument('-O', action='store_true', help='enable OS detection')
    args = parser.parse_args()

    port_scanner = PortScanner(args.t, args.p, args.O)
    port_scanner.scan()

if __name__ == '__main__':
    main()
