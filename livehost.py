import argparse
import subprocess
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1

def scan_network_arp(ip_range, timeout=2, retry=2):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    # Create an Ethernet frame to encapsulate the ARP request
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and capture the response
    answered_list = srp(arp_request_broadcast, timeout=timeout, retry=retry, verbose=False)[0]

    # Extract and print live hosts
    clients = []
    for sent, received in answered_list:
        if {'ip': received.psrc, 'mac': received.hwsrc} not in clients:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def scan_network_icmp(ip_range, timeout=2):
    # Split the IP range to get the network part and generate all possible IPs
    ip_parts = ip_range.split('.')
    base_ip = '.'.join(ip_parts[:3]) + '.'
    clients = []

    for i in range(1, 255):
        ip = base_ip + str(i)
        # Send ICMP request
        icmp_request = IP(dst=ip)/ICMP()
        response = sr1(icmp_request, timeout=timeout, verbose=False)
        if response:
            clients.append({'ip': ip, 'mac': 'N/A'})

    return clients

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("ip_range", help="IP range to scan, e.g., 192.168.1.0/24")
    parser.add_argument("--timeout", type=int, default=2, help="Timeout in seconds for each request")
    parser.add_argument("--retry", type=int, default=2, help="Number of retries for each request (only for ARP)")
    parser.add_argument("--method", choices=['arp', 'icmp'], default='arp', help="Discovery method: 'arp' or 'icmp'")
    args = parser.parse_args()

    ip_range = args.ip_range
    timeout = args.timeout
    retry = args.retry
    method = args.method

    if method == 'arp':
        live_hosts = scan_network_arp(ip_range, timeout, retry)
    elif method == 'icmp':
        live_hosts = scan_network_icmp(ip_range, timeout)

    print("Live hosts in the network:")
    for host in live_hosts:
        print(f"IP: {host['ip']}  MAC: {host['mac']}")
