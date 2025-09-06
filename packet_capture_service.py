"""
Enhanced Network Packet Capture Service with Advanced Protocol Detection
Real-time packet capture and analysis service for the Network Anomaly Detection system
"""

import time
import logging
import threading
from datetime import datetime, timezone
from queue import Queue, Empty
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass

# Import our enhanced analyzer
try:
    from enhanced_packet_analyzer import get_enhanced_analyzer, EnhancedPacketInfo
    HAS_ENHANCED_ANALYZER = True
except ImportError as e:
    logging.warning(f"Enhanced analyzer not available: {e}")
    HAS_ENHANCED_ANALYZER = False

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class CapturedPacket:
    """Data structure for captured network packets."""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    flags: Optional[str] = None
    packet_type: Optional[str] = None
    raw_features: Optional[Dict] = None
    anomaly_score: float = 0.0
    anomaly_details: Optional[List] = None

class AnomalyDetector:
    """Real-time anomaly detection for network packets"""
    
    def __init__(self, ml_model_manager=None):
        self.ml_model_manager = ml_model_manager
        self.baseline_stats = {
            'packet_sizes': [],
            'protocols': {},
            'ports': {},
            'ips': set()
        }
    
    def analyze_packet(self, packet_data: CapturedPacket) -> Dict:
        """Analyze packet for anomalies"""
        anomalies = []
        score = 0.0
        
        try:
            # Basic rule-based detection
            
            # 1. Suspicious packet sizes
            if packet_data.length > 1500:  # Larger than MTU
                anomalies.append("Large packet size detected")
                score += 0.3
            elif packet_data.length < 64:  # Smaller than minimum
                anomalies.append("Unusually small packet")
                score += 0.2
            
            # 2. Suspicious ports
            suspicious_ports = {1337, 31337, 12345, 54321, 9999, 6667, 6697}
            if packet_data.dst_port in suspicious_ports:
                anomalies.append(f"Connection to suspicious port: {packet_data.dst_port}")
                score += 0.7
            
            # 3. Protocol anomalies
            if packet_data.protocol == "ICMP" and packet_data.length > 1024:
                anomalies.append("Large ICMP packet - potential attack")
                score += 0.6
            
            # 4. TCP flag anomalies (if available)
            if packet_data.flags:
                suspicious_flags = ["SYN+FIN", "FIN+RST", "NULL", "XMAS"]
                if packet_data.flags in suspicious_flags:
                    anomalies.append(f"Suspicious TCP flags: {packet_data.flags}")
                    score += 0.8
            
            # 5. High-frequency connections (simplified)
            if hasattr(self, '_connection_count'):
                connection_key = f"{packet_data.src_ip}:{packet_data.dst_ip}"
                self._connection_count[connection_key] = self._connection_count.get(connection_key, 0) + 1
                if self._connection_count[connection_key] > 100:  # Threshold
                    anomalies.append("High frequency connection detected")
                    score += 0.4
            else:
                self._connection_count = {}
            
            # 6. ML Model Analysis (if available)
            if self.ml_model_manager and self.ml_model_manager.can_detect_anomalies():
                try:
                    # Create feature vector from packet data
                    features = [
                        packet_data.length,
                        packet_data.src_port,
                        packet_data.dst_port,
                        1.0 if packet_data.protocol == "TCP" else 0.0,
                        1.0 if packet_data.protocol == "UDP" else 0.0,
                        1.0 if packet_data.protocol == "ICMP" else 0.0
                    ]
                    
                    # Get ML prediction
                    ml_result = self.ml_model_manager.predict_anomaly(features)
                    if ml_result.get('is_anomaly', False):
                        anomalies.append("ML model detected anomaly")
                        score += ml_result.get('confidence', 0.5)
                        
                except Exception as e:
                    logger.warning(f"ML analysis failed: {e}")
            
            return {
                'anomalies': anomalies,
                'score': min(score, 1.0),  # Cap at 1.0
                'is_anomaly': score > 0.5
            }
            
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            return {
                'anomalies': [f"Analysis error: {str(e)}"],
                'score': 0.0,
                'is_anomaly': False
            }

class PacketCaptureService:
    """Service for capturing and processing network packets in real-time."""
    
    def __init__(self, ml_model_manager=None):
        self.ml_model_manager = ml_model_manager
        self.is_capturing = False
        self.capture_thread = None
        self.packet_queue = Queue(maxsize=1000)
        self.stats = {
            'total_packets': 0,
            'packets_per_protocol': {},
            'start_time': None,
            'last_packet_time': None,
            'anomalies_detected': 0
        }
        self.callbacks = []
        
    def add_callback(self, callback: Callable[[CapturedPacket], None]):
        """Add a callback function to receive captured packets."""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[CapturedPacket], None]):
        """Remove a callback function."""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def _process_packet(self, packet):
        """Process a single captured packet using direct protocol detection."""
        try:
            # Use direct protocol detector for reliable results
            try:
                from direct_protocol_detector import get_protocol_info
                protocol_info = get_protocol_info(packet)
                
                # Create packet data with detected protocols
                packet_data = CapturedPacket(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    src_ip="Unknown",
                    dst_ip="Unknown",
                    src_port=protocol_info.src_port,
                    dst_port=protocol_info.dst_port,
                    protocol=protocol_info.application_protocol,
                    length=len(packet),
                    packet_type=protocol_info.transport_protocol,
                    anomaly_score=0.0,
                    anomaly_details=[]
                )
                
                # Extract IP information if available
                from scapy.all import IP, ARP
                if packet.haslayer(IP):
                    ip = packet[IP]
                    packet_data.src_ip = ip.src
                    packet_data.dst_ip = ip.dst
                elif packet.haslayer(ARP):
                    arp = packet[ARP]
                    packet_data.src_ip = arp.psrc
                    packet_data.dst_ip = arp.pdst
                
                # Store additional protocol info
                packet_data.raw_features = {
                    'transport_protocol': protocol_info.transport_protocol,
                    'payload_size': protocol_info.payload_size,
                    'detection_method': 'direct_detector'
                }
                
            except ImportError:
                # Fallback to basic analysis if direct detector fails
                packet_data = self._basic_packet_analysis(packet)
            
            # Apply enhanced analysis if available
            if HAS_ENHANCED_ANALYZER:
                try:
                    analyzer = get_enhanced_analyzer(enable_kitsune=False)
                    enhanced_info = analyzer.analyze_packet(packet)
                    
                    # Update with enhanced analysis results
                    if enhanced_info.application_protocol != "Unknown":
                        packet_data.protocol = enhanced_info.application_protocol
                    
                    packet_data.anomaly_score = enhanced_info.anomaly_score
                    packet_data.anomaly_details = enhanced_info.anomaly_reasons
                    
                    # Add enhanced features
                    if packet_data.raw_features:
                        packet_data.raw_features.update({
                            'payload_entropy': enhanced_info.payload_entropy,
                            'kitsune_score': enhanced_info.kitsune_score,
                            'http_method': enhanced_info.http_method,
                            'dns_query': enhanced_info.dns_query
                        })
                        
                except Exception as e:
                    logger.debug(f"Enhanced analysis failed: {e}")
            
            # Update statistics with proper protocol classification
            self.stats['total_packets'] += 1
            self.stats['last_packet_time'] = packet_data.timestamp
            
            protocol = packet_data.protocol
            if protocol not in self.stats['packets_per_protocol']:
                self.stats['packets_per_protocol'][protocol] = 0
            self.stats['packets_per_protocol'][protocol] += 1
            
            # Count anomalies
            if packet_data.anomaly_score > 0.5:
                self.stats['anomalies_detected'] += 1
            
            # Add to queue for processing
            try:
                self.packet_queue.put_nowait(packet_data)
            except Exception:
                # Queue is full, skip this packet
                pass
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(packet_data)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
            
            # Store in database if available
            if hasattr(self, 'db_manager') and self.db_manager:
                try:
                    self._store_packet_in_database(packet_data)
                except Exception as e:
                    logger.error(f"Error storing packet in database: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _basic_packet_analysis(self, packet):
        """Fallback basic packet analysis when enhanced analyzer not available."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            # Initialize packet data
            packet_data = CapturedPacket(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip="Unknown",
                dst_ip="Unknown", 
                src_port=0,
                dst_port=0,
                protocol="Unknown",
                length=len(packet),
                flags=None,
                packet_type=None,
                raw_features=None,
                anomaly_score=0.0,
                anomaly_details=None
            )
            
            # Extract IP layer information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_data.src_ip = ip_layer.src
                packet_data.dst_ip = ip_layer.dst
                
                # Extract protocol-specific information
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_data.protocol = self._determine_app_protocol_from_port(tcp_layer.dport, "TCP")
                    packet_data.src_port = tcp_layer.sport
                    packet_data.dst_port = tcp_layer.dport
                    packet_data.flags = str(tcp_layer.flags)
                    
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_data.protocol = self._determine_app_protocol_from_port(udp_layer.dport, "UDP")
                    packet_data.src_port = udp_layer.sport
                    packet_data.dst_port = udp_layer.dport
                    
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    packet_data.protocol = "ICMP"
                    packet_data.packet_type = f"Type_{icmp_layer.type}"
            
            return packet_data
            
        except Exception as e:
            logger.error(f"Error in basic packet analysis: {e}")
            return CapturedPacket(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip="Unknown",
                dst_ip="Unknown",
                src_port=0,
                dst_port=0,
                protocol="Error",
                length=0,
                flags=None,
                packet_type=None,
                raw_features=None,
                anomaly_score=0.0,
                anomaly_details=None
            )
    
    def _determine_app_protocol_from_port(self, port, transport_protocol):
        """Determine application protocol from port number."""
        port_map = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3389: "RDP", 5060: "SIP", 8080: "HTTP-Alt"
        }
        
        if port in port_map:
            return port_map[port]
        else:
            return transport_protocol
    
    def _store_packet_in_database(self, packet_data):
        """Store packet data in the database."""
        try:
            if hasattr(self, 'db_manager') and self.db_manager:
                # Store packet information
                self.db_manager.store_packet({
                    'timestamp': packet_data.timestamp,
                    'src_ip': packet_data.src_ip,
                    'dst_ip': packet_data.dst_ip,
                    'src_port': packet_data.src_port,
                    'dst_port': packet_data.dst_port,
                    'protocol': packet_data.protocol,
                    'length': packet_data.length,
                    'flags': packet_data.flags or '',
                    'anomaly_score': packet_data.anomaly_score
                })
                
                # Store anomaly if detected
                if packet_data.anomaly_score > 0.5 and packet_data.anomaly_details:
                    self.db_manager.store_anomaly({
                        'timestamp': packet_data.timestamp,
                        'src_ip': packet_data.src_ip,
                        'dst_ip': packet_data.dst_ip,
                        'protocol': packet_data.protocol,
                        'anomaly_score': packet_data.anomaly_score,
                        'model_name': 'packet_analyzer',
                        'severity': 'high' if packet_data.anomaly_score > 0.8 else 'medium',
                        'description': '; '.join(packet_data.anomaly_details),
                        'details': {
                            'src_ip': packet_data.src_ip,
                            'dst_ip': packet_data.dst_ip,
                            'protocol': packet_data.protocol,
                            'score': packet_data.anomaly_score
                        }
                    })
        except Exception as e:
            logger.error(f"Error storing packet in database: {e}")
    
    def set_database_manager(self, db_manager):
        """Set the database manager for storing packets."""
        self.db_manager = db_manager
    
    def _analyze_packet_with_ml(self, packet_data: CapturedPacket):
        """Analyze packet with the ML model for anomaly detection."""
        try:
            # Temporarily disable ML analysis to debug
            logger.debug("ML analysis temporarily disabled for debugging")
            return
            
            # Extract features for ML analysis
            features = self._extract_features(packet_data)
            
            # Get current model status
            status = self.ml_model_manager.get_system_status()
            
            if status['mode'] == 'baseline_collection':
                # Add to baseline collection
                self.ml_model_manager.add_baseline_data([features])
                logger.debug(f"Added packet to baseline: {packet_data.protocol}")
                
            elif status['mode'] == 'detection':
                # Predict anomaly
                prediction = self.ml_model_manager.predict([features])
                if prediction and prediction[0] == -1:  # Anomaly detected
                    self.stats['anomalies_detected'] += 1
                    logger.warning(f"Anomaly detected in packet: {packet_data.__dict__}")
                    
        except Exception as e:
            logger.error(f"Error in ML analysis: {e}")
    
    def _extract_features(self, packet_data: CapturedPacket) -> List[float]:
        """Extract numerical features from packet data for ML analysis."""
        try:
            # Convert protocol to numerical value
            protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'Unknown': 0}
            protocol_num = protocol_map.get(packet_data.protocol, 0)
            
            # Extract basic features
            features = [
                float(packet_data.length),  # Packet size
                float(protocol_num),        # Protocol number
                float(packet_data.src_port if packet_data.src_port else 0),  # Source port
                float(packet_data.dst_port if packet_data.dst_port else 0),  # Destination port
            ]
            
            # Add time-based features
            hour = datetime.now().hour
            minute = datetime.now().minute
            features.extend([float(hour), float(minute)])
            
            # Add flags for TCP
            if packet_data.protocol == 'TCP' and packet_data.flags:
                try:
                    flags_num = int(packet_data.flags) if packet_data.flags.isdigit() else 0
                    features.append(float(flags_num))
                except:
                    features.append(0.0)
            else:
                features.append(0.0)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return [0.0] * 7  # Return default features
    
    def _capture_loop(self, count: int = None, timeout: int = None):
        """Main packet capture loop."""
        try:
            from scapy.all import sniff
            
            logger.info(f"Starting packet capture (count={count}, timeout={timeout})")
            self.stats['start_time'] = datetime.now(timezone.utc).isoformat()
            
            # Start packet capture
            sniff(
                count=count,
                timeout=timeout,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_capturing
            )
            
        except PermissionError:
            logger.error("Permission denied - try running as administrator")
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
        finally:
            self.is_capturing = False
            logger.info("Packet capture stopped")
    
    def start_capture(self, count: int = None, timeout: int = None):
        """Start packet capture in a background thread."""
        if self.is_capturing:
            logger.warning("Capture already in progress")
            return False
        
        self.is_capturing = True
        self.stats = {
            'total_packets': 0,
            'packets_per_protocol': {},
            'start_time': None,
            'last_packet_time': None,
            'anomalies_detected': 0
        }
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(count, timeout),
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info("Packet capture started")
        return True
    
    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_capturing:
            logger.warning("No capture in progress")
            return False
        
        self.is_capturing = False
        
        # Wait for thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        logger.info("Packet capture stopped")
        return True
    
    def get_status(self) -> Dict:
        """Get current capture status and statistics."""
        return {
            'is_capturing': self.is_capturing,
            'stats': self.stats.copy(),
            'queue_size': self.packet_queue.qsize()
        }
    
    def get_recent_packets(self, max_packets: int = 10) -> List[Dict]:
        """Get recent captured packets from the queue."""
        packets = []
        count = 0
        
        while count < max_packets:
            try:
                packet = self.packet_queue.get_nowait()
                packets.append(packet.__dict__)
                count += 1
            except Empty:
                break
        
        return packets
    
    def test_capture(self, count: int = 10, timeout: int = 30) -> Dict:
        """Run a test capture and return results."""
        if self.is_capturing:
            return {'error': 'Capture already in progress'}
        
        logger.info(f"Starting test capture: {count} packets, {timeout}s timeout")
        
        # Start capture
        self.start_capture(count=count, timeout=timeout)
        
        # Wait for capture to complete
        start_time = time.time()
        while self.is_capturing and (time.time() - start_time) < (timeout + 5):
            time.sleep(0.5)
        
        # Get results
        status = self.get_status()
        packets = self.get_recent_packets(max_packets=count)
        
        return {
            'success': True,
            'packets_captured': len(packets),
            'packets': packets,
            'stats': status['stats'],
            'test_duration': time.time() - start_time
        }

# Global instance for use in Flask app
packet_capture_service = None

def get_packet_capture_service(ml_model_manager=None):
    """Get or create the global packet capture service instance."""
    global packet_capture_service
    if packet_capture_service is None:
        packet_capture_service = PacketCaptureService(ml_model_manager)
    elif ml_model_manager and packet_capture_service.ml_model_manager is None:
        packet_capture_service.ml_model_manager = ml_model_manager
    return packet_capture_service
