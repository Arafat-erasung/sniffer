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


    #check for IP layers
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print(f"Source IP:      {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol:       {ip_layer.proto}")
        print(f"Packet Length:  {len(packet)} bytes")

    #check for TCP layer packets
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]

        print(f"\n🔵 TCP Packet Detected")
        print(f"   Source Port:      {tcp_layer.sport}")
        print(f"   Destination Port: {tcp_layer.dport}")
        print(f"   Flags:            {tcp_layer.flags}")

    #identify packets
    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
        print(f"    Service:                HTTP (Web Traffic)")
    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
        print(f"    Service:                HTTPS (Secure Web)")
    elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                print(f"   Service:          SSH (Secure Shell)")
    elif tcp_layer.dport == 21 or tcp_layer.sport == 21:
                print(f"   Service:          FTP (File Transfer)")

    #check for UDP
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"\n🟢 UDP Packet Detected")
        print(f"   Source Port:      {udp_layer.sport}")
        print(f"   Destination Port: {udp_layer.dport}")

        if udp_layer.dport == 53 or udp_layer.sport == 53:
              print(f"   Service:          DNS (Domain Name System)")
        elif   udp_layer.dport == 67 or udp_layer.sport == 67:
              print(f"   Service:          DHCP (Dynamic Host Config)")
    
    
    #check for ICMP packets
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print(f"\n🔴 ICMP Packet Detected")
        print(f"   Type:             {icmp_layer.type}")
        print(f"   Code:             {icmp_layer.code}")
        if icmp_layer.type == 8:
              print(f"   Message:          Echo Request (Ping)")
        elif icmp_layer.type == 0:
              print(f"   Message:          Echo Request (Pong)")

    #Display payload if available
    if packet.haslayer(Raw):
          payload = packet[Raw].load
          print(f"\n📦 Payload Preview:")
          try:
                payload_text = payload.decode('utf-8', errors='ignore')[:100]
                print(f"   {payload_text}")
          except:
                print(f"   {payload[:50].hex()}")
    else:
          print("⚠️  Non-IP Packet (ARP, etc.)")
          print("="*70)            

    
def main():
    """
    Main function to start the network sniffer
    """
    print("\n" + "🔍 NETWORK SNIFFER STARTED".center(70, "="))
    print("CodeAlpha Cybersecurity Internship - Task 1")
    print("="*70)
    print("\n⚠️  Note: Run this script with administrator/sudo privileges")
    print("📌 Press Ctrl+C to stop sniffing\n")
    print("Capturing packets...\n")
    
    try:
        # Start sniffing
        # count=0 means continuous sniffing
        # store=0 means don't store packets in memory (saves RAM)
        sniff(prn=packet_callback, store=0, count=20)
        
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print("🛑 Sniffer stopped by user")
        print("="*70)
    except PermissionError:
        print("\n❌ ERROR: Permission denied!")
        print("💡 Solution:")
        print("   Windows: Run Command Prompt as Administrator")
        print("   Linux/Mac: Run with sudo (sudo python3 network_sniffer.py)")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")


if __name__ == "__main__":
    main()

