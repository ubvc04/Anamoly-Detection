#!/usr/bin/env python3
"""
Test Live Packet Capture System
Quick test to verify packet capture functionality
"""

import time
import requests
from live_packet_capture import LivePacketCapture

def test_packet_capture():
    """Test the live packet capture system."""
    print("🔬 Testing Live Packet Capture System")
    print("=" * 50)
    
    # Create capture instance
    capture = LivePacketCapture()
    
    # Check available interfaces
    print("📡 Available Network Interfaces:")
    interfaces = capture.get_available_interfaces()
    for i, iface in enumerate(interfaces):
        print(f"  {i+1}. {iface}")
    
    if not interfaces:
        print("❌ No network interfaces found!")
        return False
    
    print(f"\n🚀 Starting packet capture...")
    
    # Start capture
    success = capture.start_capture()
    if not success:
        print("❌ Failed to start packet capture!")
        return False
    
    print("✅ Packet capture started successfully!")
    print("📊 Monitoring packets for 10 seconds...")
    
    # Monitor for 10 seconds
    for i in range(10):
        time.sleep(1)
        stats = capture.get_statistics()
        print(f"  [{i+1:2d}s] Packets captured: {stats['total_packets']}")
    
    # Generate some network traffic to test
    print("\n🌐 Generating test traffic...")
    try:
        # Make some HTTP requests to generate traffic
        requests.get("http://httpbin.org/ip", timeout=5)
        requests.get("https://httpbin.org/headers", timeout=5)
    except:
        print("  (External requests failed - using local traffic only)")
    
    # Wait a bit more
    time.sleep(2)
    
    # Get final statistics
    final_stats = capture.get_statistics()
    print(f"\n📈 Final Statistics:")
    print(f"  Total Packets: {final_stats['total_packets']}")
    print(f"  Protocols Detected: {len(final_stats['protocols'])}")
    print(f"  Protocol Breakdown:")
    for protocol, count in final_stats['protocols'].items():
        print(f"    - {protocol}: {count} packets")
    
    # Show recent packets
    recent_packets = capture.get_recent_packets(5)
    print(f"\n📡 Recent Packets (last 5):")
    for packet in recent_packets:
        print(f"  {packet['timestamp']} - {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']} [{packet['protocol']}]")
    
    # Stop capture
    capture.stop_capture()
    print("\n🛑 Packet capture stopped")
    
    # Verify we captured some packets
    if final_stats['total_packets'] > 0:
        print("✅ Test PASSED - Packets were captured successfully!")
        return True
    else:
        print("❌ Test FAILED - No packets were captured!")
        return False

if __name__ == "__main__":
    success = test_packet_capture()
    exit(0 if success else 1)
