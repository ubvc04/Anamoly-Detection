#!/usr/bin/env python3
"""
Test script to verify network packet capture functionality.
This script tests:
1. Scapy installation and basic functionality
2. Network interface detection
3. Live packet capture (10 packets)
4. Packet parsing and feature extraction
"""

import sys
import time
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_scapy_import():
    """Test if Scapy can be imported successfully."""
    try:
        from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
        logger.info("✅ Scapy imported successfully")
        return True
    except ImportError as e:
        logger.error(f"❌ Failed to import Scapy: {e}")
        return False

def test_network_interfaces():
    """Test network interface detection."""
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        logger.info(f"✅ Found {len(interfaces)} network interfaces:")
        for i, iface in enumerate(interfaces):
            logger.info(f"  {i + 1}. {iface}")
        return interfaces
    except Exception as e:
        logger.error(f"❌ Failed to get network interfaces: {e}")
        return []

def packet_callback(packet):
    """Callback function to process captured packets."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'protocol': 'Unknown'
        }
        
        # Extract basic packet information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info.update({
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto
            })
            
            # Check for TCP
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'protocol': 'TCP',
                    'flags': tcp_layer.flags
                })
            
            # Check for UDP
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'protocol': 'UDP'
                })
            
            # Check for ICMP
            elif packet.haslayer(ICMP):
                packet_info.update({
                    'protocol': 'ICMP',
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code
                })
        
        logger.info(f"📦 Captured packet: {packet_info}")
        return packet_info
        
    except Exception as e:
        logger.error(f"❌ Error processing packet: {e}")
        return None

def test_packet_capture(count=10, timeout=30):
    """Test live packet capture."""
    try:
        from scapy.all import sniff
        
        logger.info(f"🔍 Starting packet capture (capturing {count} packets, timeout {timeout}s)...")
        logger.info("💡 Tip: Generate some network traffic (browse web, ping) to see packets")
        
        # Capture packets
        packets = sniff(count=count, timeout=timeout, prn=packet_callback)
        
        if packets:
            logger.info(f"✅ Successfully captured {len(packets)} packets")
            return packets
        else:
            logger.warning("⚠️  No packets captured - this might indicate:")
            logger.warning("   • No network traffic during capture window")
            logger.warning("   • Npcap/WinPcap not properly installed")
            logger.warning("   • Insufficient permissions (try running as administrator)")
            return []
            
    except PermissionError:
        logger.error("❌ Permission denied - try running as administrator")
        return []
    except Exception as e:
        logger.error(f"❌ Packet capture failed: {e}")
        return []

def test_npcap_installation():
    """Test if Npcap is properly installed on Windows."""
    try:
        import os
        
        # Check for Npcap installation paths
        npcap_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Windows\SysWOW64\Npcap",
            r"C:\Program Files\Npcap"
        ]
        
        npcap_found = False
        for path in npcap_paths:
            if os.path.exists(path):
                logger.info(f"✅ Npcap found at: {path}")
                npcap_found = True
                
                # List files in the directory
                try:
                    files = os.listdir(path)
                    key_files = [f for f in files if f.endswith('.dll') or f.endswith('.exe')]
                    if key_files:
                        logger.info(f"   Key files: {', '.join(key_files[:5])}")
                except Exception:
                    pass
        
        if not npcap_found:
            logger.warning("⚠️  Npcap not found in standard locations")
            logger.warning("   Install from: https://npcap.com/")
            
        return npcap_found
        
    except Exception as e:
        logger.error(f"❌ Error checking Npcap installation: {e}")
        return False

def main():
    """Main test function."""
    logger.info("🚀 Starting Network Packet Capture Test")
    logger.info("=" * 60)
    
    # Test 1: Scapy import
    logger.info("Test 1: Scapy Import")
    if not test_scapy_import():
        logger.error("❌ Critical: Scapy import failed. Cannot proceed.")
        return False
    
    # Test 2: Npcap installation (Windows)
    logger.info("\nTest 2: Npcap Installation Check")
    test_npcap_installation()
    
    # Test 3: Network interfaces
    logger.info("\nTest 3: Network Interface Detection")
    interfaces = test_network_interfaces()
    if not interfaces:
        logger.error("❌ Critical: No network interfaces found. Cannot proceed.")
        return False
    
    # Test 4: Packet capture
    logger.info("\nTest 4: Live Packet Capture")
    packets = test_packet_capture(count=10, timeout=30)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("📊 TEST SUMMARY")
    logger.info("=" * 60)
    
    if packets:
        logger.info(f"✅ SUCCESS: Captured {len(packets)} packets")
        logger.info("✅ Network packet capture is working!")
        logger.info("✅ Ready to integrate with Flask application")
    else:
        logger.warning("⚠️  LIMITED SUCCESS: Scapy works but no packets captured")
        logger.warning("   • Try running as administrator")
        logger.warning("   • Ensure Npcap is installed and working")
        logger.warning("   • Check Windows firewall settings")
    
    return len(packets) > 0

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("\n🛑 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        sys.exit(1)
