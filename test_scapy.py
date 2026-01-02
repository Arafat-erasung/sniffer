"""
Test if Scapy is working properly
CodeAlpha - Diagnostic Script
"""

print("="*70)
print("SCAPY DIAGNOSTIC TEST".center(70))
print("="*70)

# Test 1: Import Scapy
print("\n1️⃣ Testing Scapy import...")
try:
    from scapy.all import *
    print("   ✅ SUCCESS: Scapy imported successfully!")
except ImportError as e:
    print(f"   ❌ FAILED: {e}")
    print("   💡 Solution: Run 'python -m pip install scapy'")
    exit()

# Test 2: Check Scapy version
print("\n2️⃣ Checking Scapy version...")
try:
    print(f"   ✅ Scapy version: {scapy.__version__}")
except:
    print("   ⚠️  Could not determine version")

# Test 3: Check network interfaces
print("\n3️⃣ Checking available network interfaces...")
try:
    interfaces = get_if_list()
    print(f"   ✅ Found {len(interfaces)} interface(s):")
    for i, iface in enumerate(interfaces, 1):
        print(f"      {i}. {iface}")
except Exception as e:
    print(f"   ❌ FAILED: {e}")

# Test 4: Check if Npcap/WinPcap is installed
print("\n4️⃣ Checking for Npcap/WinPcap...")
try:
    conf.use_pcap = True
    print("   ✅ Npcap/WinPcap detected!")
except Exception as e:
    print(f"   ❌ FAILED: {e}")
    print("   💡 Solution: Install Npcap from https://npcap.com")

# Test 5: Try to capture a single packet
print("\n5️⃣ Testing packet capture (1 packet, 10 second timeout)...")
print("   ⏳ Waiting for network traffic...")
print("   💡 TIP: Open a website or ping something to generate traffic")

try:
    packet = sniff(count=1, timeout=10)
    if packet:
        print(f"   ✅ SUCCESS: Captured {len(packet)} packet(s)!")
        print(f"   📦 Packet summary: {packet[0].summary()}")
    else:
        print("   ⚠️  No packets captured (timeout)")
        print("   💡 This might mean:")
        print("      - No network activity during test")
        print("      - Firewall blocking packet capture")
        print("      - Need to run as Administrator")
except PermissionError:
    print("   ❌ FAILED: Permission denied")
    print("   💡 Solution: Run Command Prompt as Administrator")
except Exception as e:
    print(f"   ❌ FAILED: {e}")

# Test 6: Check admin privileges (Windows)
print("\n6️⃣ Checking administrator privileges...")
import ctypes
try:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if is_admin:
        print("   ✅ Running with administrator privileges")
    else:
        print("   ❌ NOT running as administrator")
        print("   💡 Right-click Command Prompt → 'Run as Administrator'")
except:
    print("   ⚠️  Could not check admin status")

# Summary
print("\n" + "="*70)
print("DIAGNOSTIC COMPLETE".center(70))
print("="*70)
print("\n📋 Summary:")
print("   If all tests passed, your sniffer should work!")
print("   If Test 5 failed, try generating network traffic while running.")
print("   If Test 6 failed, run as Administrator.")
print("\n💡 Next step: Run your network_sniffer.py and generate traffic")
print("="*70)