# base libraries
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr1, srp
from scapy.volatile import RandShort
# from scapy.all import *

import asyncio
import nmap

# services
from core.services.serviceMacLookup import MacLookup

class NetworkScanner:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.mac_address = None
        self.mac_vendor = None
        self.os = None
        self.open_ports = []
        self.scan_results = {}

    def get_mac_address(self):
        try:
            # Send an ARP request to the IP address and get the MAC address
            arp_request = ARP(pdst=self.ip_address)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            if answered_list:
                self.mac_address = answered_list[0][1].hwsrc
        except Exception as e:
            print(f"Error getting MAC address: {e}")

    async def get_mac_vendor(self):
        try:
            # Use the MacLookup class to get the MAC vendor
            if self.mac_address:
                mac_lookup = MacLookup()
                self.mac_vendor = await mac_lookup.get_vendor(self.mac_address)
        except Exception as e:
            print(f"Error getting MAC vendor: {e}")

    def get_os(self):
        try:
            # Use nmap's OS detection feature
            nm = nmap.PortScanner()
            nm.scan(self.ip_address, arguments='-O')
            if 'osmatch' in nm[self.ip_address]:
                os = nm[self.ip_address]['osmatch'][0]['name']
                self.os = os
            else:
                # If nmap doesn't detect the OS, try to use scapy
                self.os = self.get_os_scapy()
        except Exception as e:
            print(f"Error getting OS: {e}")

    def get_os_scapy(self):
        try:
            # Use scapy's TCP SYN packet to detect the OS
            packet = IP(dst=self.ip_address)/TCP(dport=80, flags="S")
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        # If the response is a SYN-ACK packet, it's likely a Windows or Linux system
                        return "Windows or Linux"
                    elif response.getlayer(TCP).flags == 0x14:
                        # If the response is a RST-ACK packet, it's likely a macOS system
                        return "macOS"
                    else:
                        # If the response doesn't match any known OS, return "Unknown"
                        return "Unknown"
        except Exception as e:
            print(f"Error getting OS using scapy: {e}")
            return "Unknown"

    def get_open_ports(self):
        try:
            # Scan for open ports using TCP SYN packets
            common_ports = [22, 80, 443, 110, 143, 161, 389, 445, 3389]
            for port in common_ports:
                packet = IP(dst=self.ip_address)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1, verbose=False)
                if response:
                    if response.haslayer(TCP):
                        if response.getlayer(TCP).flags == 0x12:
                            self.open_ports.append(port)
        except Exception as e:
            print(f"Error getting open ports: {e}")

    async def scan(self):
        self.get_mac_address()
        await self.get_mac_vendor()
        self.get_os()
        self.get_open_ports()

    def get_results(self):
        return {
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'mac_vendor': self.mac_vendor,
            'os': self.os,
            'open_ports': self.open_ports
        }

# Usage
# async def main():
#     scanner = NetworkScanner("192.168.1.1")  # Replace with the IP address you want to scan
#     await scanner.scan()
#     print(scanner.get_results())

# asyncio.run(main())