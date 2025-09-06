"""
Enhanced Network Packet Analyzer with Advanced Protocol Detection
Comprehensive packet analysis for network anomaly detection with Kitsune integration
"""

import logging
import socket
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

try:
    from scapy.all import (
        IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP, 
        Raw, Ether, Dot1Q
    )
    from scapy.layers.http import HTTP, HTTPRequest
    HAS_SCAPY = True
    
    # Try to import TLS support, but don't fail if not available
    try:
        from scapy.layers.tls import TLS
        HAS_TLS = True
    except ImportError:
        logging.info("TLS layer not available in Scapy - TLS detection disabled")
        HAS_TLS = False
        TLS = None
        
except ImportError as e:
    logging.warning(f"Scapy import error: {e}")
    HAS_SCAPY = False
    HAS_TLS = False

try:
    import KitNET as kt
    HAS_KITSUNE = True
except ImportError:
    try:
        from kitsune import Kitsune
        HAS_KITSUNE = True
    except ImportError:
        try:
            from simple_kitnet import SimpleKitNet, get_kitsune_analyzer
            HAS_KITSUNE = True
        except ImportError:
            logging.warning("Kitsune not available - will use fallback anomaly detection")
            HAS_KITSUNE = False

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class EnhancedPacketInfo:
    """Enhanced packet information with comprehensive protocol detection."""
    
    # Basic packet info
    timestamp: str
    raw_length: int
    capture_length: int
    
    # Network layer (L3)
    src_ip: str = "Unknown"
    dst_ip: str = "Unknown"
    ip_version: int = 0
    ttl: int = 0
    ip_flags: str = ""
    ip_protocol: str = "Unknown"
    
    # Transport layer (L4)
    src_port: int = 0
    dst_port: int = 0
    transport_protocol: str = "Unknown"
    tcp_flags: str = ""
    tcp_window: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    udp_length: int = 0
    
    # Application layer (L7)
    application_protocol: str = "Unknown"
    http_method: str = ""
    http_host: str = ""
    http_uri: str = ""
    dns_query: str = ""
    dns_response_code: int = 0
    tls_version: str = ""
    tls_cipher: str = ""
    
    # Data link layer (L2)
    src_mac: str = "Unknown"
    dst_mac: str = "Unknown"
    vlan_id: int = 0
    ethernet_type: str = "Unknown"
    
    # Payload information
    payload_size: int = 0
    payload_entropy: float = 0.0
    has_payload: bool = False
    
    # Analysis results
    protocol_confidence: float = 1.0
    anomaly_score: float = 0.0
    anomaly_reasons: List[str] = field(default_factory=list)
    kitsune_score: float = 0.0
    
    # Feature vector for ML
    feature_vector: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'transport_protocol': self.transport_protocol,
            'application_protocol': self.application_protocol,
            'length': self.raw_length,
            'payload_size': self.payload_size,
            'tcp_flags': self.tcp_flags,
            'http_method': self.http_method,
            'dns_query': self.dns_query,
            'anomaly_score': self.anomaly_score,
            'kitsune_score': self.kitsune_score,
            'anomaly_reasons': self.anomaly_reasons
        }

class EnhancedPacketAnalyzer:
    """Enhanced packet analyzer with comprehensive protocol detection and Kitsune integration."""
    
    def __init__(self, enable_kitsune: bool = True):
        self.enable_kitsune = enable_kitsune and HAS_KITSUNE
        self.kitsune_detector = None
        self.packet_count = 0
        
        # Protocol detection mappings
        self.port_to_protocol = {
            # Well-known ports
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
            123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
            179: "BGP", 194: "IRC", 443: "HTTPS", 465: "SMTPS",
            587: "SMTP", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        # Initialize Kitsune if available
        if self.enable_kitsune:
            self._initialize_kitsune()
    
    def _initialize_kitsune(self):
        """Initialize Kitsune anomaly detector."""
        try:
            if HAS_KITSUNE:
                # Try different Kitsune import methods
                try:
                    import KitNET as kt
                    # Initialize KitNET (newer version)
                    self.kitsune_detector = kt.KitNET(
                        n=115,  # Number of features
                        maxAE=10,  # Maximum autoencoders
                        FMgrace=100,  # Feature mapping grace period
                        ADgrace=1000,  # Anomaly detection grace period
                        learning_rate=0.1,
                        hidden_ratio=0.75
                    )
                    logger.info("KitNET anomaly detector initialized")
                except ImportError:
                    # Fallback to basic implementation
                    self.kitsune_detector = None
                    logger.info("Using fallback anomaly detection")
            else:
                logger.warning("Kitsune not available - using fallback detection")
        except Exception as e:
            logger.error(f"Failed to initialize Kitsune: {e}")
            self.enable_kitsune = False
    
    def analyze_packet(self, packet) -> EnhancedPacketInfo:
        """Analyze a packet and extract comprehensive information."""
        if not HAS_SCAPY:
            return self._create_minimal_packet_info()
        
        packet_info = EnhancedPacketInfo(
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_length=len(packet),
            capture_length=len(packet)
        )
        
        try:
            # Extract Ethernet/Data Link layer info
            self._extract_datalink_info(packet, packet_info)
            
            # Extract Network layer (IP) info
            self._extract_network_info(packet, packet_info)
            
            # Extract Transport layer info
            self._extract_transport_info(packet, packet_info)
            
            # Extract Application layer info
            self._extract_application_info(packet, packet_info)
            
            # Extract payload information
            self._extract_payload_info(packet, packet_info)
            
            # Create feature vector
            self._create_feature_vector(packet_info)
            
            # Perform Kitsune analysis
            if self.enable_kitsune and self.kitsune_detector:
                self._analyze_with_kitsune(packet_info)
            
            # Perform rule-based anomaly detection
            self._detect_anomalies(packet_info)
            
            self.packet_count += 1
            
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            packet_info.anomaly_reasons.append(f"Analysis error: {str(e)}")
        
        return packet_info
    
    def _extract_datalink_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract data link layer information."""
        try:
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_info.src_mac = eth.src
                packet_info.dst_mac = eth.dst
                packet_info.ethernet_type = f"0x{eth.type:04x}"
                
                # Check for VLAN tags
                if packet.haslayer(Dot1Q):
                    vlan = packet[Dot1Q]
                    packet_info.vlan_id = vlan.vlan
        except Exception as e:
            logger.debug(f"Error extracting datalink info: {e}")
    
    def _extract_network_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract network layer information."""
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info.src_ip = ip.src
                packet_info.dst_ip = ip.dst
                packet_info.ip_version = ip.version
                packet_info.ttl = ip.ttl
                packet_info.ip_flags = str(ip.flags)
                packet_info.ip_protocol = self._get_ip_protocol_name(ip.proto)
                
            elif packet.haslayer(IPv6):
                ipv6 = packet[IPv6]
                packet_info.src_ip = ipv6.src
                packet_info.dst_ip = ipv6.dst
                packet_info.ip_version = 6
                packet_info.ttl = ipv6.hlim
                packet_info.ip_protocol = "IPv6"
                
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info.src_ip = arp.psrc
                packet_info.dst_ip = arp.pdst
                packet_info.ip_protocol = "ARP"
                packet_info.application_protocol = "ARP"
                
        except Exception as e:
            logger.debug(f"Error extracting network info: {e}")
    
    def _extract_transport_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract transport layer information."""
        try:
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info.transport_protocol = "TCP"
                packet_info.src_port = tcp.sport
                packet_info.dst_port = tcp.dport
                packet_info.tcp_flags = str(tcp.flags)
                packet_info.tcp_window = tcp.window
                packet_info.tcp_seq = tcp.seq
                packet_info.tcp_ack = tcp.ack
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info.transport_protocol = "UDP"
                packet_info.src_port = udp.sport
                packet_info.dst_port = udp.dport
                packet_info.udp_length = udp.len
                
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                packet_info.transport_protocol = "ICMP"
                packet_info.application_protocol = f"ICMP-Type{icmp.type}"
                
        except Exception as e:
            logger.debug(f"Error extracting transport info: {e}")
    
    def _extract_application_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract application layer information."""
        try:
            # Determine application protocol based on ports and packet inspection
            app_protocol = self._determine_application_protocol(packet, packet_info)
            packet_info.application_protocol = app_protocol
            
            # Extract protocol-specific information
            if packet.haslayer(DNS):
                self._extract_dns_info(packet, packet_info)
            elif packet.haslayer(HTTP) or packet.haslayer(HTTPRequest):
                self._extract_http_info(packet, packet_info)
            elif HAS_TLS and TLS and packet.haslayer(TLS):
                self._extract_tls_info(packet, packet_info)
            elif packet.haslayer(DHCP):
                packet_info.application_protocol = "DHCP"
                
        except Exception as e:
            logger.debug(f"Error extracting application info: {e}")
    
    def _determine_application_protocol(self, packet, packet_info: EnhancedPacketInfo) -> str:
        """Determine application protocol using multiple methods."""
        
        # Method 1: Check for specific protocol layers
        if packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(HTTP) or packet.haslayer(HTTPRequest):
            return "HTTP"
        elif HAS_TLS and TLS and packet.haslayer(TLS):
            return "TLS/SSL"
        elif packet.haslayer(DHCP):
            return "DHCP"
        elif packet.haslayer(ARP):
            return "ARP"
        
        # Method 2: Port-based detection
        if packet_info.transport_protocol in ["TCP", "UDP"]:
            # Check destination port first
            if packet_info.dst_port in self.port_to_protocol:
                return self.port_to_protocol[packet_info.dst_port]
            # Check source port
            elif packet_info.src_port in self.port_to_protocol:
                return self.port_to_protocol[packet_info.src_port]
        
        # Method 3: Payload inspection for common protocols
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            return self._inspect_payload_for_protocol(payload, packet_info)
        
        # Method 4: Default based on transport protocol
        if packet_info.transport_protocol == "ICMP":
            return "ICMP"
        elif packet_info.transport_protocol in ["TCP", "UDP"]:
            return f"{packet_info.transport_protocol}"
        
        return "Unknown"
    
    def _inspect_payload_for_protocol(self, payload: bytes, packet_info: EnhancedPacketInfo) -> str:
        """Inspect payload to determine application protocol."""
        try:
            if len(payload) < 4:
                return "Unknown"
            
            payload_str = payload[:100].decode('utf-8', errors='ignore').upper()
            
            # HTTP detection
            if any(method in payload_str for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                return "HTTP"
            elif 'HTTP/1.' in payload_str or 'HTTP/2' in payload_str:
                return "HTTP"
            
            # HTTPS/TLS detection
            elif payload[0:3] == b'\x16\x03\x01' or payload[0:3] == b'\x16\x03\x03':
                return "TLS/SSL"
            
            # FTP detection
            elif b'220 ' in payload[:10] or b'USER ' in payload[:10]:
                return "FTP"
            
            # SMTP detection  
            elif b'220 ' in payload[:10] and b'SMTP' in payload[:50]:
                return "SMTP"
            elif any(cmd in payload[:20] for cmd in [b'HELO ', b'EHLO ', b'MAIL FROM:', b'RCPT TO:']):
                return "SMTP"
            
            # SSH detection
            elif payload.startswith(b'SSH-'):
                return "SSH"
            
            # DNS over TCP detection
            elif packet_info.dst_port == 53 or packet_info.src_port == 53:
                return "DNS"
            
            # SNMP detection
            elif packet_info.dst_port == 161 or packet_info.src_port == 161:
                return "SNMP"
            
        except Exception as e:
            logger.debug(f"Error inspecting payload: {e}")
        
        return "Unknown"
    
    def _extract_dns_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract DNS-specific information."""
        try:
            dns = packet[DNS]
            packet_info.application_protocol = "DNS"
            
            if dns.qd:  # Query
                packet_info.dns_query = dns.qd.qname.decode('utf-8', errors='ignore')
            
            packet_info.dns_response_code = dns.rcode
            
        except Exception as e:
            logger.debug(f"Error extracting DNS info: {e}")
    
    def _extract_http_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract HTTP-specific information."""
        try:
            if packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                packet_info.application_protocol = "HTTP"
                packet_info.http_method = http.Method.decode('utf-8', errors='ignore')
                packet_info.http_host = http.Host.decode('utf-8', errors='ignore') if http.Host else ""
                packet_info.http_uri = http.Path.decode('utf-8', errors='ignore') if http.Path else ""
                
        except Exception as e:
            logger.debug(f"Error extracting HTTP info: {e}")
    
    def _extract_tls_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract TLS/SSL-specific information."""
        try:
            if HAS_TLS and TLS and packet.haslayer(TLS):
                tls = packet[TLS]
                packet_info.application_protocol = "TLS/SSL"
                # Extract version and cipher info if available
                
        except Exception as e:
            logger.debug(f"Error extracting TLS info: {e}")
    
    def _extract_payload_info(self, packet, packet_info: EnhancedPacketInfo):
        """Extract payload information."""
        try:
            if packet.haslayer(Raw):
                payload = packet[Raw]
                packet_info.payload_size = len(payload)
                packet_info.has_payload = True
                
                # Calculate payload entropy
                packet_info.payload_entropy = self._calculate_entropy(bytes(payload))
            
        except Exception as e:
            logger.debug(f"Error extracting payload info: {e}")
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        try:
            if len(data) == 0:
                return 0.0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    freq = count / data_len
                    entropy -= freq * (freq.bit_length() - 1)
            
            return entropy
            
        except Exception as e:
            logger.debug(f"Error calculating entropy: {e}")
            return 0.0
    
    def _create_feature_vector(self, packet_info: EnhancedPacketInfo):
        """Create feature vector for ML analysis."""
        try:
            features = [
                # Basic packet features
                float(packet_info.raw_length),
                float(packet_info.payload_size),
                float(packet_info.payload_entropy),
                
                # Network layer features
                float(packet_info.ip_version),
                float(packet_info.ttl),
                
                # Transport layer features
                float(packet_info.src_port),
                float(packet_info.dst_port),
                float(packet_info.tcp_window),
                float(packet_info.udp_length),
                
                # Protocol flags (binary)
                1.0 if packet_info.transport_protocol == "TCP" else 0.0,
                1.0 if packet_info.transport_protocol == "UDP" else 0.0,
                1.0 if packet_info.transport_protocol == "ICMP" else 0.0,
                1.0 if packet_info.application_protocol == "HTTP" else 0.0,
                1.0 if packet_info.application_protocol == "HTTPS" else 0.0,
                1.0 if packet_info.application_protocol == "DNS" else 0.0,
                
                # Time-based features
                float(datetime.now().hour),
                float(datetime.now().minute),
            ]
            
            packet_info.feature_vector = features
            
        except Exception as e:
            logger.debug(f"Error creating feature vector: {e}")
            packet_info.feature_vector = [0.0] * 17
    
    def _analyze_with_kitsune(self, packet_info: EnhancedPacketInfo):
        """Analyze packet with Kitsune anomaly detector."""
        try:
            if not self.kitsune_detector:
                return
            
            # Create Kitsune feature vector (115 features expected)
            kitsune_features = self._create_kitsune_features(packet_info)
            
            # Get anomaly score from Kitsune
            try:
                # Try KitNET interface
                rmse = self.kitsune_detector.process(kitsune_features)
                packet_info.kitsune_score = float(rmse) if rmse is not None else 0.0
            except AttributeError:
                try:
                    # Try older Kitsune interface
                    rmse = self.kitsune_detector.proc_next_vector(kitsune_features)
                    packet_info.kitsune_score = float(rmse) if rmse is not None else 0.0
                except Exception:
                    # Fallback scoring
                    packet_info.kitsune_score = 0.0
            
        except Exception as e:
            logger.debug(f"Error in Kitsune analysis: {e}")
            packet_info.kitsune_score = 0.0
    
    def _create_kitsune_features(self, packet_info: EnhancedPacketInfo) -> List[float]:
        """Create Kitsune-compatible feature vector (115 features)."""
        try:
            # Start with basic features
            features = packet_info.feature_vector.copy()
            
            # Pad or truncate to 115 features as expected by Kitsune
            while len(features) < 115:
                features.append(0.0)
            
            return features[:115]
            
        except Exception as e:
            logger.debug(f"Error creating Kitsune features: {e}")
            return [0.0] * 115
    
    def _detect_anomalies(self, packet_info: EnhancedPacketInfo):
        """Perform rule-based anomaly detection."""
        anomalies = []
        score = 0.0
        
        try:
            # Large packet size
            if packet_info.raw_length > 1500:
                anomalies.append("Unusually large packet size")
                score += 0.3
            
            # Small packet size
            elif packet_info.raw_length < 64 and packet_info.transport_protocol != "ICMP":
                anomalies.append("Unusually small packet size")
                score += 0.2
            
            # Suspicious ports
            suspicious_ports = {1337, 31337, 12345, 54321, 9999, 4444, 5555}
            if packet_info.dst_port in suspicious_ports or packet_info.src_port in suspicious_ports:
                anomalies.append("Connection to suspicious port")
                score += 0.7
            
            # High entropy payload (possible encryption/compression)
            if packet_info.payload_entropy > 7.5 and packet_info.application_protocol not in ["TLS/SSL", "SSH"]:
                anomalies.append("High entropy payload detected")
                score += 0.4
            
            # Unusual TCP flags
            if packet_info.tcp_flags:
                suspicious_flag_combos = ["FUS", "FSRPAU", "SR", "SF"]
                if any(combo in packet_info.tcp_flags for combo in suspicious_flag_combos):
                    anomalies.append("Suspicious TCP flag combination")
                    score += 0.6
            
            # DNS anomalies
            if packet_info.application_protocol == "DNS":
                if packet_info.payload_size > 512:
                    anomalies.append("Unusually large DNS query/response")
                    score += 0.5
            
            # HTTP anomalies
            if packet_info.application_protocol == "HTTP":
                if packet_info.http_method and packet_info.http_method not in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]:
                    anomalies.append("Unusual HTTP method")
                    score += 0.4
            
            # Kitsune score threshold
            if packet_info.kitsune_score > 0.1:  # Adjust threshold as needed
                anomalies.append("Kitsune anomaly detector triggered")
                score += packet_info.kitsune_score
            
            packet_info.anomaly_reasons = anomalies
            packet_info.anomaly_score = min(score, 1.0)
            
        except Exception as e:
            logger.debug(f"Error in anomaly detection: {e}")
    
    def _get_ip_protocol_name(self, proto_num: int) -> str:
        """Get IP protocol name from number."""
        protocol_map = {
            1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP",
            41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH"
        }
        return protocol_map.get(proto_num, f"Protocol-{proto_num}")
    
    def _create_minimal_packet_info(self) -> EnhancedPacketInfo:
        """Create minimal packet info when Scapy is not available."""
        return EnhancedPacketInfo(
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_length=0,
            capture_length=0,
            anomaly_reasons=["Scapy not available for detailed analysis"]
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            'packets_analyzed': self.packet_count,
            'kitsune_enabled': self.enable_kitsune,
            'scapy_available': HAS_SCAPY,
            'supported_protocols': list(self.port_to_protocol.values())
        }

# Global instance
enhanced_analyzer = None

def get_enhanced_analyzer(enable_kitsune: bool = True) -> EnhancedPacketAnalyzer:
    """Get or create global enhanced analyzer instance."""
    global enhanced_analyzer
    if enhanced_analyzer is None:
        enhanced_analyzer = EnhancedPacketAnalyzer(enable_kitsune=enable_kitsune)
    return enhanced_analyzer
