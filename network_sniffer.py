"""
Basic Network Sniffer - CodeAlpha Cybersecurity Internship
Author: Arafat Erasung
Task 1: Network Packet Capture and Analysis
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

def packet_callback(packet):
    """
    callback function to process each captured packet
    """

    #get current time
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "="*70)
    print(f"[{timestamp}] PACKET CAPTURED")
    print("="*70)

    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print(f"Source IP:      {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol:       {ip_layer.proto}")
        print(f"Packet Length:  {len(packet)} bytes")
