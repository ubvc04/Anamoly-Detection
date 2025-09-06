"""
Direct Protocol Detection Fix
Enhanced protocol detection that actually works
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger(__name__)

@dataclass
class ProtocolInfo:
    """Simple protocol information structure."""
    transport_protocol: str = "Unknown"
    application_protocol: str = "Unknown"
    src_port: int = 0
    dst_port: int = 0
    payload_size: int = 0

class DirectProtocolDetector:
    """Direct and reliable protocol detector."""
    
    def __init__(self):
        # Common port mappings
        self.tcp_ports = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        self.udp_ports = {
            53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
            123: "NTP", 161: "SNMP", 162: "SNMP-Trap",
            514: "Syslog", 1194: "OpenVPN", 5060: "SIP"
        }
    
    def analyze_packet(self, packet) -> ProtocolInfo:
        """Analyze packet and return protocol information."""
        info = ProtocolInfo()
        
        if not HAS_SCAPY:
            return info
        
        try:
            # Check for IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                
                # TCP analysis
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    info.transport_protocol = "TCP"
                    info.src_port = tcp.sport
                    info.dst_port = tcp.dport
                    
                    # Determine application protocol
                    info.application_protocol = self._get_tcp_app_protocol(tcp, packet)
                
                # UDP analysis
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    info.transport_protocol = "UDP"
                    info.src_port = udp.sport
                    info.dst_port = udp.dport
                    
                    # Determine application protocol
                    info.application_protocol = self._get_udp_app_protocol(udp, packet)
                
                # ICMP analysis
                elif packet.haslayer(ICMP):
                    info.transport_protocol = "ICMP"
                    info.application_protocol = "ICMP"
                
                # Get payload size
                if packet.haslayer(Raw):
                    info.payload_size = len(packet[Raw])
            
            # ARP analysis
            elif packet.haslayer(ARP):
                info.transport_protocol = "ARP"
                info.application_protocol = "ARP"
            
            # DNS analysis (can be over TCP or UDP)
            if packet.haslayer(DNS):
                info.application_protocol = "DNS"
            
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
        
        return info
    
    def _get_tcp_app_protocol(self, tcp, packet) -> str:
        """Determine TCP application protocol."""
        
        # Check well-known ports first
        if tcp.dport in self.tcp_ports:
            return self.tcp_ports[tcp.dport]
        elif tcp.sport in self.tcp_ports:
            return self.tcp_ports[tcp.sport]
        
        # Check payload for HTTP
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            if self._is_http_payload(payload):
                if tcp.dport == 443 or tcp.sport == 443:
                    return "HTTPS"
                else:
                    return "HTTP"
        
        # Default to TCP
        return "TCP"
    
    def _get_udp_app_protocol(self, udp, packet) -> str:
        """Determine UDP application protocol."""
        
        # Check well-known ports
        if udp.dport in self.udp_ports:
            return self.udp_ports[udp.dport]
        elif udp.sport in self.udp_ports:
            return self.udp_ports[udp.sport]
        
        # Special cases
        if packet.haslayer(DNS):
            return "DNS"
        
        # Default to UDP
        return "UDP"
    
    def _is_http_payload(self, payload: bytes) -> bool:
        """Check if payload looks like HTTP."""
        try:
            if len(payload) < 4:
                return False
            
            payload_str = payload[:100].decode('utf-8', errors='ignore').upper()
            
            # Check for HTTP methods
            http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']
            if any(method in payload_str for method in http_methods):
                return True
            
            # Check for HTTP response
            if payload_str.startswith('HTTP/'):
                return True
            
            return False
            
        except Exception:
            return False

# Global detector instance
direct_detector = DirectProtocolDetector()

def get_protocol_info(packet) -> ProtocolInfo:
    """Get protocol information for a packet."""
    return direct_detector.analyze_packet(packet)
