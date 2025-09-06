#!/usr/bin/env python3
"""
Live Packet Capture System
Real-time packet capture with protocol detection and web display
"""

import time
import json
import logging
import threading
from datetime import datetime, timezone
from collections import deque
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, get_if_list
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("ERROR: Scapy not available - packet capture will not work")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LivePacket:
    """Simple packet structure for live display."""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    transport: str
    size: int
    info: str

class LivePacketCapture:
    """Real-time packet capture for live display."""
    
    def __init__(self, max_packets=100):
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.is_capturing = False
        self.capture_thread = None
        self.stats = {
            'total': 0,
            'protocols': {},
            'start_time': None
        }
        
        # Port to protocol mapping
        self.port_protocols = {
            # TCP ports
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            # UDP ports
            67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
            161: "SNMP", 162: "SNMP-Trap", 514: "Syslog"
        }
    
    def _detect_protocol(self, packet) -> str:
        """Detect application protocol from packet."""
        try:
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                # Check common ports
                if tcp.dport in self.port_protocols:
                    return self.port_protocols[tcp.dport]
                elif tcp.sport in self.port_protocols:
                    return self.port_protocols[tcp.sport]
                return "TCP"
            
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                # Check common ports
                if udp.dport in self.port_protocols:
                    return self.port_protocols[udp.dport]
                elif udp.sport in self.port_protocols:
                    return self.port_protocols[udp.sport]
                return "UDP"
            
            elif packet.haslayer(ICMP):
                return "ICMP"
            
            elif packet.haslayer(ARP):
                return "ARP"
            
            elif packet.haslayer(DNS):
                return "DNS"
            
            else:
                return "Unknown"
                
        except Exception:
            return "Unknown"
    
    def _get_packet_info(self, packet) -> str:
        """Get additional packet information."""
        try:
            info = ""
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                if tcp.flags.P: flags.append("PSH")
                if tcp.flags.U: flags.append("URG")
                if flags:
                    info = f"Flags: {','.join(flags)}"
            
            elif packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:  # Query
                    if dns.qd:
                        info = f"Query: {dns.qd.qname.decode()}"
                else:  # Response
                    info = f"Response: {dns.rcode}"
            
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                info = f"ARP {arp.op}"
            
            return info
            
        except Exception:
            return ""
    
    def _process_packet(self, packet):
        """Process captured packet."""
        try:
            # Extract basic information
            timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
            src_ip = "Unknown"
            dst_ip = "Unknown"
            src_port = 0
            dst_port = 0
            transport = "Unknown"
            
            # Get IP addresses
            if packet.haslayer(IP):
                ip = packet[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    transport = "TCP"
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    transport = "UDP"
                elif packet.haslayer(ICMP):
                    transport = "ICMP"
                    
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                src_ip = arp.psrc
                dst_ip = arp.pdst
                transport = "ARP"
            
            # Detect application protocol
            protocol = self._detect_protocol(packet)
            
            # Get additional info
            info = self._get_packet_info(packet)
            
            # Create packet object
            live_packet = LivePacket(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                transport=transport,
                size=len(packet),
                info=info
            )
            
            # Add to packet list
            self.packets.append(live_packet)
            
            # Update statistics
            self.stats['total'] += 1
            if protocol not in self.stats['protocols']:
                self.stats['protocols'][protocol] = 0
            self.stats['protocols'][protocol] += 1
            
            logger.debug(f"Captured: {src_ip}:{src_port} → {dst_ip}:{dst_port} [{protocol}]")
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start_capture(self, interface=None):
        """Start packet capture."""
        if not HAS_SCAPY:
            logger.error("Scapy not available - cannot start capture")
            return False
        
        if self.is_capturing:
            logger.warning("Capture already running")
            return True
        
        try:
            self.is_capturing = True
            self.stats['start_time'] = datetime.now(timezone.utc).isoformat()
            
            def capture_worker():
                try:
                    logger.info(f"Starting packet capture on interface: {interface or 'default'}")
                    # Start sniffing packets
                    sniff(
                        iface=interface,
                        prn=self._process_packet,
                        stop_filter=lambda x: not self.is_capturing,
                        store=False  # Don't store packets in memory
                    )
                except Exception as e:
                    logger.error(f"Capture error: {e}")
                finally:
                    self.is_capturing = False
            
            self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
            self.capture_thread.start()
            
            logger.info("Packet capture started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            self.is_capturing = False
            return False
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_recent_packets(self, count=50) -> List[Dict]:
        """Get recent packets as dictionaries."""
        recent = list(self.packets)[-count:] if self.packets else []
        return [asdict(packet) for packet in recent]
    
    def get_statistics(self) -> Dict:
        """Get capture statistics."""
        return {
            'total_packets': self.stats['total'],
            'protocols': dict(self.stats['protocols']),
            'is_capturing': self.is_capturing,
            'start_time': self.stats['start_time'],
            'current_time': datetime.now(timezone.utc).isoformat()
        }
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces."""
        if not HAS_SCAPY:
            return []
        
        try:
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []

# Global capture instance
live_capture = LivePacketCapture()

def get_live_capture():
    """Get the global live capture instance."""
    return live_capture

if __name__ == "__main__":
    # Test the capture system
    capture = LivePacketCapture()
    
    print("Available interfaces:")
    for iface in capture.get_available_interfaces():
        print(f"  - {iface}")
    
    print("\nStarting packet capture...")
    capture.start_capture()
    
    try:
        while True:
            time.sleep(2)
            stats = capture.get_statistics()
            print(f"Captured {stats['total_packets']} packets")
            
            if stats['total_packets'] > 0:
                recent = capture.get_recent_packets(5)
                print("Recent packets:")
                for packet in recent:
                    print(f"  {packet['timestamp']} - {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']} [{packet['protocol']}]")
            
    except KeyboardInterrupt:
        print("\nStopping capture...")
        capture.stop_capture()
