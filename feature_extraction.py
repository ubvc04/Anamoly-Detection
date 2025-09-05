"""
Feature Extraction Module
Extracts comprehensive features from network traffic for machine learning models
"""

import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict, Counter
import ipaddress
import re
from dataclasses import dataclass
from config.config import config
from database import db_manager

@dataclass
class NetworkFeatures:
    """Container for extracted network features"""
    flow_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    features: Dict[str, float]
    feature_names: List[str]

class ProtocolAnalyzer:
    """Analyzes protocol distribution and patterns"""
    
    def __init__(self):
        """Initialize protocol analyzer"""
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.well_known_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 587: 'SMTP-SSL', 465: 'SMTP-SSL', 3389: 'RDP',
            3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
    
    def analyze_protocol(self, protocol: str, source_port: int, dest_port: int) -> Dict[str, float]:
        """
        Analyze protocol characteristics
        
        Args:
            protocol: Protocol name
            source_port: Source port
            dest_port: Destination port
            
        Returns:
            Dictionary of protocol features
        """
        features = {}
        
        # Protocol type indicators
        features['is_tcp'] = 1.0 if protocol == 'TCP' else 0.0
        features['is_udp'] = 1.0 if protocol == 'UDP' else 0.0
        features['is_icmp'] = 1.0 if protocol == 'ICMP' else 0.0
        features['is_dns'] = 1.0 if protocol == 'DNS' else 0.0
        features['is_http'] = 1.0 if dest_port in [80, 8080] else 0.0
        features['is_https'] = 1.0 if dest_port in [443, 8443] else 0.0
        features['is_ssh'] = 1.0 if dest_port == 22 else 0.0
        features['is_ftp'] = 1.0 if dest_port in [20, 21] else 0.0
        
        # Port analysis
        features['source_port'] = float(source_port or 0)
        features['dest_port'] = float(dest_port or 0)
        features['is_well_known_port'] = 1.0 if dest_port in self.well_known_ports else 0.0
        features['is_ephemeral_port'] = 1.0 if (source_port or 0) > 32768 else 0.0
        features['is_privileged_port'] = 1.0 if (dest_port or 0) < 1024 else 0.0
        
        # Suspicious port patterns
        features['is_suspicious_port'] = self._is_suspicious_port(dest_port)
        features['port_scan_indicator'] = self._detect_port_scan_pattern(source_port, dest_port)
        
        return features
    
    def _is_suspicious_port(self, port: Optional[int]) -> float:
        """Check if port is commonly associated with malware"""
        if not port:
            return 0.0
        
        suspicious_ports = {
            1337, 31337, 12345, 54321, 9999, 6667, 6697,  # Common backdoor ports
            4444, 5555, 7777, 8888, 1234, 2222, 3333,     # Malware ports
            666, 999, 13, 79, 111, 513, 514, 515          # Potentially risky ports
        }
        
        return 1.0 if port in suspicious_ports else 0.0
    
    def _detect_port_scan_pattern(self, source_port: Optional[int], dest_port: Optional[int]) -> float:
        """Detect potential port scanning patterns"""
        if not dest_port:
            return 0.0
        
        # Sequential port access pattern
        if hasattr(self, '_last_dest_port'):
            if abs(dest_port - self._last_dest_port) == 1:
                return 1.0
        
        self._last_dest_port = dest_port
        return 0.0

class IPAnalyzer:
    """Analyzes IP address patterns and characteristics"""
    
    def __init__(self):
        """Initialize IP analyzer"""
        self.ip_stats = defaultdict(int)
        self.country_stats = defaultdict(int)
        
    def analyze_ip_features(self, source_ip: str, dest_ip: str) -> Dict[str, float]:
        """
        Analyze IP address features
        
        Args:
            source_ip: Source IP address
            dest_ip: Destination IP address
            
        Returns:
            Dictionary of IP features
        """
        features = {}
        
        try:
            src_ip_obj = ipaddress.ip_address(source_ip)
            dst_ip_obj = ipaddress.ip_address(dest_ip)
            
            # IP version
            features['is_ipv4'] = 1.0 if src_ip_obj.version == 4 else 0.0
            features['is_ipv6'] = 1.0 if src_ip_obj.version == 6 else 0.0
            
            # Network classification
            features['src_is_private'] = 1.0 if src_ip_obj.is_private else 0.0
            features['dst_is_private'] = 1.0 if dst_ip_obj.is_private else 0.0
            features['src_is_multicast'] = 1.0 if src_ip_obj.is_multicast else 0.0
            features['dst_is_multicast'] = 1.0 if dst_ip_obj.is_multicast else 0.0
            features['src_is_loopback'] = 1.0 if src_ip_obj.is_loopback else 0.0
            features['dst_is_loopback'] = 1.0 if dst_ip_obj.is_loopback else 0.0
            
            # Same network detection
            features['same_network'] = self._is_same_network(src_ip_obj, dst_ip_obj)
            
            # Geographic features (simplified)
            features['is_local_communication'] = 1.0 if (src_ip_obj.is_private and dst_ip_obj.is_private) else 0.0
            features['is_outbound'] = 1.0 if (src_ip_obj.is_private and not dst_ip_obj.is_private) else 0.0
            features['is_inbound'] = 1.0 if (not src_ip_obj.is_private and dst_ip_obj.is_private) else 0.0
            
            # Suspicious IP patterns
            features['is_suspicious_ip'] = self._is_suspicious_ip_pattern(source_ip, dest_ip)
            
        except ValueError as e:
            logging.warning(f"Invalid IP address: {e}")
            # Set default values for invalid IPs
            for key in ['is_ipv4', 'is_ipv6', 'src_is_private', 'dst_is_private',
                       'src_is_multicast', 'dst_is_multicast', 'src_is_loopback',
                       'dst_is_loopback', 'same_network', 'is_local_communication',
                       'is_outbound', 'is_inbound', 'is_suspicious_ip']:
                features[key] = 0.0
        
        return features
    
    def _is_same_network(self, ip1: ipaddress.IPv4Address, ip2: ipaddress.IPv4Address) -> float:
        """Check if IPs are in the same network"""
        try:
            # Check common private networks
            networks = [
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12')
            ]
            
            for network in networks:
                if ip1 in network and ip2 in network:
                    return 1.0
            
            return 0.0
        except:
            return 0.0
    
    def _is_suspicious_ip_pattern(self, source_ip: str, dest_ip: str) -> float:
        """Detect suspicious IP patterns"""
        # Check for IP addresses that might indicate scanning or attacks
        suspicious_patterns = [
            r'^0\.', r'^127\.', r'^169\.254\.', r'^224\.', r'^255\.',  # Special use
            r'^192\.0\.2\.', r'^198\.51\.100\.', r'^203\.0\.113\.',     # Test networks
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, dest_ip):
                return 1.0
        
        return 0.0

class FlowAnalyzer:
    """Analyzes network flow characteristics"""
    
    def __init__(self):
        """Initialize flow analyzer"""
        self.flow_cache = {}
    
    def analyze_flow_features(self, flow_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Analyze flow-based features
        
        Args:
            flow_data: Flow information dictionary
            
        Returns:
            Dictionary of flow features
        """
        features = {}
        
        # Basic flow metrics
        features['duration'] = float(flow_data.get('duration', 0))
        features['packet_count'] = float(flow_data.get('packet_count', 0))
        features['byte_count'] = float(flow_data.get('byte_count', 0))
        features['packets_per_second'] = float(flow_data.get('packets_per_second', 0))
        features['bytes_per_second'] = float(flow_data.get('bytes_per_second', 0))
        
        # Packet size statistics
        features['avg_packet_size'] = float(flow_data.get('avg_packet_size', 0))
        features['std_packet_size'] = float(flow_data.get('std_packet_size', 0))
        features['min_packet_size'] = float(flow_data.get('min_packet_size', 0))
        features['max_packet_size'] = float(flow_data.get('max_packet_size', 0))
        
        # Derived metrics
        if features['avg_packet_size'] > 0:
            features['packet_size_variance'] = features['std_packet_size'] / features['avg_packet_size']
        else:
            features['packet_size_variance'] = 0.0
        
        # Flow characteristics
        features['is_short_flow'] = 1.0 if features['duration'] < 1.0 else 0.0
        features['is_long_flow'] = 1.0 if features['duration'] > 300.0 else 0.0
        features['is_bulk_flow'] = 1.0 if features['byte_count'] > 1000000 else 0.0  # 1MB+
        features['is_small_flow'] = 1.0 if features['byte_count'] < 1000 else 0.0    # <1KB
        
        # Rate-based features
        features['high_packet_rate'] = 1.0 if features['packets_per_second'] > 100 else 0.0
        features['high_byte_rate'] = 1.0 if features['bytes_per_second'] > 1000000 else 0.0  # 1MB/s
        
        # TCP flags analysis
        tcp_flags_count = flow_data.get('tcp_flags_count', {})
        if isinstance(tcp_flags_count, str):
            try:
                import json
                tcp_flags_count = json.loads(tcp_flags_count)
            except:
                tcp_flags_count = {}
        
        features['syn_count'] = float(tcp_flags_count.get('SYN', 0))
        features['ack_count'] = float(tcp_flags_count.get('ACK', 0))
        features['fin_count'] = float(tcp_flags_count.get('FIN', 0))
        features['rst_count'] = float(tcp_flags_count.get('RST', 0))
        features['psh_count'] = float(tcp_flags_count.get('PSH', 0))
        features['urg_count'] = float(tcp_flags_count.get('URG', 0))
        
        # Anomaly indicators
        features['connection_failed'] = 1.0 if (features['syn_count'] > 0 and features['ack_count'] == 0) else 0.0
        features['connection_reset'] = 1.0 if features['rst_count'] > 0 else 0.0
        features['incomplete_connection'] = 1.0 if (features['syn_count'] > 0 and features['fin_count'] == 0) else 0.0
        
        return features

class TemporalAnalyzer:
    """Analyzes temporal patterns in network traffic"""
    
    def __init__(self):
        """Initialize temporal analyzer"""
        self.hourly_stats = defaultdict(int)
        self.daily_stats = defaultdict(int)
    
    def analyze_temporal_features(self, timestamp: datetime) -> Dict[str, float]:
        """
        Analyze temporal features
        
        Args:
            timestamp: Event timestamp
            
        Returns:
            Dictionary of temporal features
        """
        features = {}
        
        # Time-based features
        features['hour_of_day'] = float(timestamp.hour)
        features['day_of_week'] = float(timestamp.weekday())
        features['is_weekend'] = 1.0 if timestamp.weekday() >= 5 else 0.0
        features['is_business_hours'] = 1.0 if 9 <= timestamp.hour <= 17 else 0.0
        features['is_night_time'] = 1.0 if timestamp.hour < 6 or timestamp.hour > 22 else 0.0
        
        # Cyclical encoding for time features
        features['hour_sin'] = np.sin(2 * np.pi * timestamp.hour / 24)
        features['hour_cos'] = np.cos(2 * np.pi * timestamp.hour / 24)
        features['day_sin'] = np.sin(2 * np.pi * timestamp.weekday() / 7)
        features['day_cos'] = np.cos(2 * np.pi * timestamp.weekday() / 7)
        
        return features

class BehavioralAnalyzer:
    """Analyzes behavioral patterns for anomaly detection"""
    
    def __init__(self, window_hours: int = 24):
        """
        Initialize behavioral analyzer
        
        Args:
            window_hours: Time window for behavior analysis
        """
        self.window_hours = window_hours
        self.ip_behavior = defaultdict(lambda: defaultdict(list))
        self.port_behavior = defaultdict(list)
    
    def analyze_behavioral_features(self, source_ip: str, dest_ip: str, 
                                  dest_port: Optional[int], protocol: str,
                                  timestamp: datetime) -> Dict[str, float]:
        """
        Analyze behavioral features
        
        Args:
            source_ip: Source IP address
            dest_ip: Destination IP address
            dest_port: Destination port
            protocol: Protocol
            timestamp: Event timestamp
            
        Returns:
            Dictionary of behavioral features
        """
        features = {}
        
        # Get recent behavior data
        recent_data = self._get_recent_behavior(timestamp)
        
        # IP-based behavior
        source_connections = recent_data.get('source_connections', {}).get(source_ip, [])
        dest_connections = recent_data.get('dest_connections', {}).get(dest_ip, [])
        
        features['source_connection_count'] = float(len(source_connections))
        features['dest_connection_count'] = float(len(dest_connections))
        features['unique_dest_ips'] = float(len(set(conn['dest_ip'] for conn in source_connections)))
        features['unique_source_ips'] = float(len(set(conn['source_ip'] for conn in dest_connections)))
        
        # Port scanning detection
        unique_ports = set(conn.get('dest_port') for conn in source_connections if conn.get('dest_port'))
        features['unique_dest_ports'] = float(len(unique_ports))
        features['port_scan_indicator'] = 1.0 if len(unique_ports) > 10 else 0.0
        
        # Protocol diversity
        protocols = [conn.get('protocol') for conn in source_connections]
        features['protocol_diversity'] = float(len(set(protocols)))
        
        # Connection patterns
        features['is_new_connection'] = 1.0 if not self._has_recent_connection(
            source_ip, dest_ip, dest_port, recent_data) else 0.0
        
        # Frequency-based features
        features['connection_frequency'] = self._calculate_connection_frequency(
            source_ip, dest_ip, recent_data)
        
        return features
    
    def _get_recent_behavior(self, timestamp: datetime) -> Dict[str, Any]:
        """Get recent behavioral data from database"""
        try:
            cutoff_time = timestamp - timedelta(hours=self.window_hours)
            
            # Get recent flows from database
            recent_flows = db_manager.get_recent_flows(hours=self.window_hours)
            
            # Organize by source and destination
            behavior_data = {
                'source_connections': defaultdict(list),
                'dest_connections': defaultdict(list)
            }
            
            for flow in recent_flows:
                source_ip = flow.get('source_ip')
                dest_ip = flow.get('dest_ip')
                
                if source_ip:
                    behavior_data['source_connections'][source_ip].append(flow)
                if dest_ip:
                    behavior_data['dest_connections'][dest_ip].append(flow)
            
            return behavior_data
            
        except Exception as e:
            logging.error(f"Error getting recent behavior: {e}")
            return {'source_connections': {}, 'dest_connections': {}}
    
    def _has_recent_connection(self, source_ip: str, dest_ip: str, dest_port: Optional[int],
                             recent_data: Dict[str, Any]) -> bool:
        """Check if similar connection exists in recent data"""
        source_connections = recent_data.get('source_connections', {}).get(source_ip, [])
        
        for conn in source_connections:
            if (conn.get('dest_ip') == dest_ip and 
                conn.get('dest_port') == dest_port):
                return True
        
        return False
    
    def _calculate_connection_frequency(self, source_ip: str, dest_ip: str,
                                      recent_data: Dict[str, Any]) -> float:
        """Calculate connection frequency between IPs"""
        source_connections = recent_data.get('source_connections', {}).get(source_ip, [])
        
        matching_connections = [
            conn for conn in source_connections 
            if conn.get('dest_ip') == dest_ip
        ]
        
        return float(len(matching_connections))

class FeatureExtractor:
    """Main feature extraction class"""
    
    def __init__(self):
        """Initialize feature extractor"""
        self.protocol_analyzer = ProtocolAnalyzer()
        self.ip_analyzer = IPAnalyzer()
        self.flow_analyzer = FlowAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        # Feature scaling parameters (will be learned from data)
        self.feature_stats = {}
        self.feature_names = []
    
    def extract_packet_features(self, packet_info) -> NetworkFeatures:
        """
        Extract features from packet information
        
        Args:
            packet_info: PacketInfo object
            
        Returns:
            NetworkFeatures object
        """
        try:
            features = {}
            
            # Protocol features
            protocol_features = self.protocol_analyzer.analyze_protocol(
                packet_info.protocol, packet_info.source_port, packet_info.dest_port
            )
            features.update(protocol_features)
            
            # IP features
            ip_features = self.ip_analyzer.analyze_ip_features(
                packet_info.source_ip, packet_info.dest_ip
            )
            features.update(ip_features)
            
            # Temporal features
            temporal_features = self.temporal_analyzer.analyze_temporal_features(
                packet_info.timestamp
            )
            features.update(temporal_features)
            
            # Behavioral features
            behavioral_features = self.behavioral_analyzer.analyze_behavioral_features(
                packet_info.source_ip, packet_info.dest_ip,
                packet_info.dest_port, packet_info.protocol,
                packet_info.timestamp
            )
            features.update(behavioral_features)
            
            # Additional packet-specific features
            features['packet_size'] = float(packet_info.packet_size)
            features['payload_size'] = float(packet_info.payload_size or 0)
            features['ttl'] = float(packet_info.ttl or 0)
            features['window_size'] = float(packet_info.window_size or 0)
            
            # Calculate payload ratio
            if packet_info.packet_size > 0:
                features['payload_ratio'] = features['payload_size'] / features['packet_size']
            else:
                features['payload_ratio'] = 0.0
            
            # Get feature names
            feature_names = sorted(features.keys())
            
            return NetworkFeatures(
                flow_id=packet_info.flow_id,
                timestamp=packet_info.timestamp,
                source_ip=packet_info.source_ip,
                dest_ip=packet_info.dest_ip,
                protocol=packet_info.protocol,
                features=features,
                feature_names=feature_names
            )
            
        except Exception as e:
            logging.error(f"Error extracting packet features: {e}")
            return None
    
    def extract_flow_features(self, flow_data: Dict[str, Any]) -> NetworkFeatures:
        """
        Extract features from flow data
        
        Args:
            flow_data: Flow information dictionary
            
        Returns:
            NetworkFeatures object
        """
        try:
            features = {}
            
            # Flow-based features
            flow_features = self.flow_analyzer.analyze_flow_features(flow_data)
            features.update(flow_features)
            
            # Protocol features
            protocol_features = self.protocol_analyzer.analyze_protocol(
                flow_data.get('protocol', ''),
                flow_data.get('source_port'),
                flow_data.get('dest_port')
            )
            features.update(protocol_features)
            
            # IP features
            ip_features = self.ip_analyzer.analyze_ip_features(
                flow_data.get('source_ip', ''),
                flow_data.get('dest_ip', '')
            )
            features.update(ip_features)
            
            # Temporal features
            timestamp = flow_data.get('start_time')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif timestamp is None:
                timestamp = datetime.now()
            
            temporal_features = self.temporal_analyzer.analyze_temporal_features(timestamp)
            features.update(temporal_features)
            
            # Behavioral features
            behavioral_features = self.behavioral_analyzer.analyze_behavioral_features(
                flow_data.get('source_ip', ''),
                flow_data.get('dest_ip', ''),
                flow_data.get('dest_port'),
                flow_data.get('protocol', ''),
                timestamp
            )
            features.update(behavioral_features)
            
            # Get feature names
            feature_names = sorted(features.keys())
            
            return NetworkFeatures(
                flow_id=flow_data.get('flow_id', ''),
                timestamp=timestamp,
                source_ip=flow_data.get('source_ip', ''),
                dest_ip=flow_data.get('dest_ip', ''),
                protocol=flow_data.get('protocol', ''),
                features=features,
                feature_names=feature_names
            )
            
        except Exception as e:
            logging.error(f"Error extracting flow features: {e}")
            return None
    
    def normalize_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """
        Normalize features using learned statistics
        
        Args:
            features: Raw features dictionary
            
        Returns:
            Normalized features dictionary
        """
        normalized = {}
        
        for feature_name, value in features.items():
            if feature_name in self.feature_stats:
                stats = self.feature_stats[feature_name]
                mean = stats.get('mean', 0)
                std = stats.get('std', 1)
                
                # Z-score normalization
                if std > 0:
                    normalized[feature_name] = (value - mean) / std
                else:
                    normalized[feature_name] = 0.0
            else:
                normalized[feature_name] = value
        
        return normalized
    
    def update_feature_statistics(self, feature_data: List[NetworkFeatures]) -> None:
        """
        Update feature statistics for normalization
        
        Args:
            feature_data: List of NetworkFeatures objects
        """
        if not feature_data:
            return
        
        try:
            # Convert to DataFrame for easier statistics calculation
            feature_vectors = []
            for nf in feature_data:
                feature_vectors.append(nf.features)
            
            df = pd.DataFrame(feature_vectors)
            
            # Calculate statistics for each feature
            self.feature_stats = {}
            for column in df.columns:
                if df[column].dtype in ['int64', 'float64']:
                    self.feature_stats[column] = {
                        'mean': float(df[column].mean()),
                        'std': float(df[column].std()),
                        'min': float(df[column].min()),
                        'max': float(df[column].max())
                    }
            
            # Update feature names
            self.feature_names = list(df.columns)
            
            logging.info(f"Updated statistics for {len(self.feature_names)} features")
            
        except Exception as e:
            logging.error(f"Error updating feature statistics: {e}")
    
    def get_feature_vector(self, features: NetworkFeatures, normalize: bool = True) -> np.ndarray:
        """
        Convert NetworkFeatures to numpy array
        
        Args:
            features: NetworkFeatures object
            normalize: Whether to normalize features
            
        Returns:
            Numpy array of feature values
        """
        try:
            if normalize:
                feature_dict = self.normalize_features(features.features)
            else:
                feature_dict = features.features
            
            # Ensure consistent feature ordering
            if not self.feature_names:
                self.feature_names = sorted(feature_dict.keys())
            
            # Create feature vector
            vector = []
            for feature_name in self.feature_names:
                vector.append(feature_dict.get(feature_name, 0.0))
            
            return np.array(vector, dtype=np.float32)
            
        except Exception as e:
            logging.error(f"Error creating feature vector: {e}")
            return np.array([])
    
    def save_features_to_database(self, features: NetworkFeatures) -> None:
        """
        Save extracted features to database
        
        Args:
            features: NetworkFeatures object
        """
        try:
            feature_data = {
                'timestamp': features.timestamp,
                'flow_id': features.flow_id,
                'features': list(features.features.values()),
                'feature_names': features.feature_names,
                'source_ip': features.source_ip,
                'dest_ip': features.dest_ip,
                'protocol': features.protocol
            }
            
            db_manager.insert_features(feature_data)
            
        except Exception as e:
            logging.error(f"Error saving features to database: {e}")

# Global feature extractor instance
feature_extractor = FeatureExtractor()
