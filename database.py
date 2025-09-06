"""
Database Management Module
Handles all database operations for the network anomaly detection system
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import (Boolean, Column, DateTime, Float, Integer, String,
                        Text, create_engine, func)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from config.config import config

# Create base class for SQLAlchemy models
Base = declarative_base()

class NetworkPacket(Base):
    """Network packet data model"""
    __tablename__ = 'network_packets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String(45))  # IPv6 support
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    packet_size = Column(Integer)
    tcp_flags = Column(String(20))
    flow_id = Column(String(100))
    interface = Column(String(50))
    raw_data = Column(Text)  # JSON serialized packet data

class NetworkFlow(Base):
    """Network flow statistics model"""
    __tablename__ = 'network_flows'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(String(100), unique=True)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration = Column(Float)
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    packets_per_second = Column(Float)
    bytes_per_second = Column(Float)
    avg_packet_size = Column(Float)
    std_packet_size = Column(Float)
    min_packet_size = Column(Integer)
    max_packet_size = Column(Integer)
    tcp_flags_count = Column(Text)  # JSON serialized flag counts

class ExtractedFeatures(Base):
    """Extracted features for ML model"""
    __tablename__ = 'extracted_features'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    flow_id = Column(String(100))
    features = Column(Text)  # JSON serialized feature vector
    feature_names = Column(Text)  # JSON serialized feature names
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    protocol = Column(String(10))

class AnomalyDetection(Base):
    """Anomaly detection results model"""
    __tablename__ = 'anomaly_detections'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    flow_id = Column(String(100))
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    protocol = Column(String(10))
    anomaly_score = Column(Float)
    model_name = Column(String(50))
    is_anomaly = Column(Boolean)
    severity = Column(String(20))  # low, medium, high, critical
    description = Column(Text)
    features = Column(Text)  # JSON serialized features that led to detection
    false_positive = Column(Boolean, default=False)  # User feedback

class ModelMetadata(Base):
    """ML model metadata and performance metrics"""
    __tablename__ = 'model_metadata'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_name = Column(String(100))
    model_type = Column(String(50))
    training_timestamp = Column(DateTime, default=datetime.utcnow)
    model_path = Column(String(500))
    training_samples = Column(Integer)
    test_samples = Column(Integer)
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    parameters = Column(Text)  # JSON serialized model parameters
    feature_importance = Column(Text)  # JSON serialized feature importance
    is_active = Column(Boolean, default=True)

class SystemConfiguration(Base):
    """System configuration storage"""
    __tablename__ = 'system_configuration'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(200), unique=True)
    config_value = Column(Text)
    config_type = Column(String(50))  # string, integer, float, boolean, json
    timestamp = Column(DateTime, default=datetime.utcnow)
    description = Column(Text)

class DatabaseManager:
    """Handles all database operations"""
    
    def __init__(self):
        """Initialize database manager"""
        self.engine = None
        self.session_maker = None
        self.lock = threading.Lock()
        self._initialize_database()
        
    def _initialize_database(self) -> None:
        """Initialize database connection and create tables"""
        try:
            db_url = config.get_database_url()
            
            # Create directory for SQLite database
            if 'sqlite' in db_url:
                db_path = db_url.replace('sqlite:///', '')
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Create engine with connection pooling for SQLite
            if 'sqlite' in db_url:
                self.engine = create_engine(
                    db_url,
                    poolclass=StaticPool,
                    connect_args={
                        'check_same_thread': False,
                        'timeout': 30
                    },
                    echo=config.get('app.debug', False)
                )
            else:
                self.engine = create_engine(db_url, echo=config.get('app.debug', False))
            
            # Create session maker
            self.session_maker = sessionmaker(bind=self.engine)
            
            # Create all tables
            Base.metadata.create_all(self.engine)
            
            logging.info("Database initialized successfully")
            
        except Exception as e:
            logging.error(f"Error initializing database: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get database session"""
        return self.session_maker()
    
    def insert_packet(self, packet_data: Dict[str, Any]) -> None:
        """
        Insert network packet data
        
        Args:
            packet_data: Dictionary containing packet information
        """
        try:
            with self.get_session() as session:
                packet = NetworkPacket(
                    timestamp=packet_data.get('timestamp', datetime.utcnow()),
                    source_ip=packet_data.get('source_ip'),
                    dest_ip=packet_data.get('dest_ip'),
                    source_port=packet_data.get('source_port'),
                    dest_port=packet_data.get('dest_port'),
                    protocol=packet_data.get('protocol'),
                    packet_size=packet_data.get('packet_size'),
                    tcp_flags=packet_data.get('tcp_flags'),
                    flow_id=packet_data.get('flow_id'),
                    interface=packet_data.get('interface'),
                    raw_data=json.dumps(packet_data.get('raw_data', {}))
                )
                session.add(packet)
                session.commit()
                
        except Exception as e:
            logging.error(f"Error inserting packet: {e}")
    
    def insert_flow(self, flow_data: Dict[str, Any]) -> None:
        """
        Insert network flow data
        
        Args:
            flow_data: Dictionary containing flow information
        """
        try:
            with self.get_session() as session:
                # Check if flow already exists
                existing_flow = session.query(NetworkFlow).filter_by(
                    flow_id=flow_data.get('flow_id')
                ).first()
                
                if existing_flow:
                    # Update existing flow
                    for key, value in flow_data.items():
                        if key == 'tcp_flags_count' and isinstance(value, dict):
                            value = json.dumps(value)
                        setattr(existing_flow, key, value)
                else:
                    # Create new flow
                    tcp_flags_count = flow_data.get('tcp_flags_count', {})
                    if isinstance(tcp_flags_count, dict):
                        tcp_flags_count = json.dumps(tcp_flags_count)
                    
                    flow = NetworkFlow(
                        flow_id=flow_data.get('flow_id'),
                        start_time=flow_data.get('start_time'),
                        end_time=flow_data.get('end_time'),
                        duration=flow_data.get('duration'),
                        source_ip=flow_data.get('source_ip'),
                        dest_ip=flow_data.get('dest_ip'),
                        source_port=flow_data.get('source_port'),
                        dest_port=flow_data.get('dest_port'),
                        protocol=flow_data.get('protocol'),
                        packet_count=flow_data.get('packet_count'),
                        byte_count=flow_data.get('byte_count'),
                        packets_per_second=flow_data.get('packets_per_second'),
                        bytes_per_second=flow_data.get('bytes_per_second'),
                        avg_packet_size=flow_data.get('avg_packet_size'),
                        std_packet_size=flow_data.get('std_packet_size'),
                        min_packet_size=flow_data.get('min_packet_size'),
                        max_packet_size=flow_data.get('max_packet_size'),
                        tcp_flags_count=tcp_flags_count
                    )
                    session.add(flow)
                
                session.commit()
                
        except Exception as e:
            logging.error(f"Error inserting flow: {e}")
    
    def insert_features(self, feature_data: Dict[str, Any]) -> None:
        """
        Insert extracted features
        
        Args:
            feature_data: Dictionary containing feature information
        """
        try:
            with self.get_session() as session:
                features = ExtractedFeatures(
                    timestamp=feature_data.get('timestamp', datetime.utcnow()),
                    flow_id=feature_data.get('flow_id'),
                    features=json.dumps(feature_data.get('features', [])),
                    feature_names=json.dumps(feature_data.get('feature_names', [])),
                    source_ip=feature_data.get('source_ip'),
                    dest_ip=feature_data.get('dest_ip'),
                    protocol=feature_data.get('protocol')
                )
                session.add(features)
                session.commit()
                
        except Exception as e:
            logging.error(f"Error inserting features: {e}")
    
    def insert_anomaly(self, anomaly_data: Dict[str, Any]) -> None:
        """
        Insert anomaly detection result
        
        Args:
            anomaly_data: Dictionary containing anomaly information
        """
        try:
            with self.get_session() as session:
                anomaly = AnomalyDetection(
                    timestamp=anomaly_data.get('timestamp', datetime.utcnow()),
                    flow_id=anomaly_data.get('flow_id'),
                    source_ip=anomaly_data.get('source_ip'),
                    dest_ip=anomaly_data.get('dest_ip'),
                    protocol=anomaly_data.get('protocol'),
                    anomaly_score=anomaly_data.get('anomaly_score'),
                    model_name=anomaly_data.get('model_name'),
                    is_anomaly=anomaly_data.get('is_anomaly'),
                    severity=anomaly_data.get('severity'),
                    description=anomaly_data.get('description'),
                    features=json.dumps(anomaly_data.get('features', {}))
                )
                session.add(anomaly)
                session.commit()
                
        except Exception as e:
            logging.error(f"Error inserting anomaly: {e}")
    
    def insert_model_metadata(self, model_data: Dict[str, Any]) -> None:
        """
        Insert model metadata
        
        Args:
            model_data: Dictionary containing model information
        """
        try:
            with self.get_session() as session:
                # Deactivate old models of the same type
                session.query(ModelMetadata).filter_by(
                    model_name=model_data.get('model_name'),
                    model_type=model_data.get('model_type')
                ).update({'is_active': False})
                
                # Insert new model metadata
                metadata = ModelMetadata(
                    model_name=model_data.get('model_name'),
                    model_type=model_data.get('model_type'),
                    training_timestamp=model_data.get('training_timestamp', datetime.utcnow()),
                    model_path=model_data.get('model_path'),
                    training_samples=model_data.get('training_samples'),
                    test_samples=model_data.get('test_samples'),
                    accuracy=model_data.get('accuracy'),
                    precision=model_data.get('precision'),
                    recall=model_data.get('recall'),
                    f1_score=model_data.get('f1_score'),
                    parameters=json.dumps(model_data.get('parameters', {})),
                    feature_importance=json.dumps(model_data.get('feature_importance', {})),
                    is_active=True
                )
                session.add(metadata)
                session.commit()
                
        except Exception as e:
            logging.error(f"Error inserting model metadata: {e}")
    
    def get_recent_flows(self, hours: int = 24, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get recent network flows
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of flows to return
            
        Returns:
            List of flow dictionaries
        """
        try:
            with self.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                flows = session.query(NetworkFlow).filter(
                    NetworkFlow.start_time >= cutoff_time
                ).order_by(NetworkFlow.start_time.desc()).limit(limit).all()
                
                return [self._flow_to_dict(flow) for flow in flows]
                
        except Exception as e:
            logging.error(f"Error getting recent flows: {e}")
            return []
    
    def get_recent_anomalies(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get recent anomaly detections
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of anomaly dictionaries
        """
        try:
            with self.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                anomalies = session.query(AnomalyDetection).filter(
                    AnomalyDetection.timestamp >= cutoff_time,
                    AnomalyDetection.is_anomaly == True
                ).order_by(AnomalyDetection.timestamp.desc()).all()
                
                return [self._anomaly_to_dict(anomaly) for anomaly in anomalies]
                
        except Exception as e:
            logging.error(f"Error getting recent anomalies: {e}")
            return []
    
    def get_training_data(self, days: int = 7) -> Dict[str, Any]:
        """
        Get training data for ML models
        
        Args:
            days: Number of days of data to retrieve
            
        Returns:
            Dictionary with training data
        """
        try:
            with self.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(days=days)
                
                # Query for extracted features
                features = session.query(ExtractedFeatures).filter(
                    ExtractedFeatures.timestamp >= cutoff_time
                ).all()
                
                if not features:
                    return {'features': [], 'labels': [], 'feature_names': []}
                
                # Convert to dictionary format
                data = []
                feature_names = []
                for feature in features:
                    feature_dict = json.loads(feature.features)
                    names = json.loads(feature.feature_names)
                    if not feature_names:
                        feature_names = names
                    
                    row = {name: feature_dict.get(str(i), 0) 
                          for i, name in enumerate(names)}
                    row['timestamp'] = feature.timestamp.isoformat()
                    row['flow_id'] = feature.flow_id
                    data.append(row)
                
                return {
                    'features': data,
                    'feature_names': feature_names,
                    'count': len(data)
                }
                
        except Exception as e:
            logging.error(f"Error getting training data: {e}")
            return {'features': [], 'labels': [], 'feature_names': []}
    
    def get_recent_traffic(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent network traffic data for baseline collection
        
        Args:
            limit: Maximum number of records to retrieve
            
        Returns:
            List of traffic data dictionaries
        """
        try:
            with self.get_session() as session:
                # Get recent packets
                packets = session.query(NetworkPacket).order_by(
                    NetworkPacket.timestamp.desc()
                ).limit(limit).all()
                
                traffic_data = []
                for packet in packets:
                    # Convert packet to feature-like format
                    traffic_dict = {
                        'packet_size': packet.packet_size or 64,
                        'protocol': self._protocol_to_number(packet.protocol),
                        'port': packet.dest_port or 80,
                        'flags': self._tcp_flags_to_number(packet.tcp_flags),
                        'ttl': 64,  # Default TTL
                        'timestamp': packet.timestamp.isoformat(),
                        'source_ip': packet.source_ip,
                        'dest_ip': packet.dest_ip,
                        'flow_id': packet.flow_id
                    }
                    traffic_data.append(traffic_dict)
                
                return traffic_data
                
        except Exception as e:
            logging.error(f"Error getting recent traffic: {e}")
            return []
    
    def _protocol_to_number(self, protocol: str) -> int:
        """Convert protocol string to number"""
        protocol_map = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'HTTP': 6,
            'HTTPS': 6,
            'FTP': 6,
            'SSH': 6,
            'TELNET': 6,
            'SMTP': 6,
            'DNS': 17
        }
        return protocol_map.get(protocol, 6)  # Default to TCP
    
    def _tcp_flags_to_number(self, flags: str) -> int:
        """Convert TCP flags string to number"""
        if not flags:
            return 0
        
        flag_values = {
            'FIN': 1,
            'SYN': 2,
            'RST': 4,
            'PSH': 8,
            'ACK': 16,
            'URG': 32,
            'ECE': 64,
            'CWR': 128
        }
        
        total = 0
        for flag in flags.split(','):
            flag = flag.strip().upper()
            total += flag_values.get(flag, 0)
        
        return total

    def cleanup_old_data(self) -> None:
        """Clean up old data based on retention settings"""
        try:
            with self.get_session() as session:
                now = datetime.utcnow()
                
                # Clean up old packets
                packet_retention = config.get('database.retention.raw_packets', 7)
                packet_cutoff = now - timedelta(days=packet_retention)
                deleted_packets = session.query(NetworkPacket).filter(
                    NetworkPacket.timestamp < packet_cutoff
                ).delete()
                
                # Clean up old features
                feature_retention = config.get('database.retention.features', 30)
                feature_cutoff = now - timedelta(days=feature_retention)
                deleted_features = session.query(ExtractedFeatures).filter(
                    ExtractedFeatures.timestamp < feature_cutoff
                ).delete()
                
                # Clean up old anomalies (keep longer for analysis)
                anomaly_retention = config.get('database.retention.anomalies', 90)
                anomaly_cutoff = now - timedelta(days=anomaly_retention)
                deleted_anomalies = session.query(AnomalyDetection).filter(
                    AnomalyDetection.timestamp < anomaly_cutoff
                ).delete()
                
                session.commit()
                
                logging.info(f"Cleaned up old data: {deleted_packets} packets, "
                           f"{deleted_features} features, {deleted_anomalies} anomalies")
                
        except Exception as e:
            logging.error(f"Error cleaning up old data: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics
        
        Returns:
            Dictionary with database statistics
        """
        try:
            with self.get_session() as session:
                stats = {}
                
                # Count records
                stats['total_packets'] = session.query(NetworkPacket).count()
                stats['total_flows'] = session.query(NetworkFlow).count()
                stats['total_features'] = session.query(ExtractedFeatures).count()
                stats['total_anomalies'] = session.query(AnomalyDetection).count()
                stats['active_models'] = session.query(ModelMetadata).filter_by(is_active=True).count()
                
                # Recent data (last 24 hours)
                cutoff_24h = datetime.utcnow() - timedelta(hours=24)
                stats['recent_packets'] = session.query(NetworkPacket).filter(
                    NetworkPacket.timestamp >= cutoff_24h
                ).count()
                stats['recent_anomalies'] = session.query(AnomalyDetection).filter(
                    AnomalyDetection.timestamp >= cutoff_24h,
                    AnomalyDetection.is_anomaly == True
                ).count()
                
                return stats
                
        except Exception as e:
            logging.error(f"Error getting statistics: {e}")
            return {}
    
    def get_protocol_packet_count(self, protocol: str) -> int:
        """
        Get packet count for a specific protocol
        
        Args:
            protocol: Protocol name (case-insensitive)
            
        Returns:
            Number of packets for the protocol
        """
        try:
            with self.get_session() as session:
                # For recent activity (last 24 hours), case-insensitive search
                cutoff_24h = datetime.utcnow() - timedelta(hours=24)
                count = session.query(NetworkPacket).filter(
                    NetworkPacket.timestamp >= cutoff_24h,
                    NetworkPacket.protocol.ilike(f'%{protocol}%')
                ).count()
                return count
                
        except Exception as e:
            logging.error(f"Error getting protocol count for {protocol}: {e}")
            return 0
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Get distribution of protocols in recent packets
        
        Returns:
            Dictionary with protocol names and counts
        """
        try:
            with self.get_session() as session:
                # Get protocol distribution for last 24 hours
                cutoff_24h = datetime.utcnow() - timedelta(hours=24)
                
                # Query for protocol counts
                protocol_counts = session.query(
                    NetworkPacket.protocol,
                    func.count(NetworkPacket.id).label('count')
                ).filter(
                    NetworkPacket.timestamp >= cutoff_24h
                ).group_by(NetworkPacket.protocol).all()
                
                # Convert to dictionary
                distribution = {}
                for protocol, count in protocol_counts:
                    # Clean up protocol names
                    clean_protocol = protocol.upper() if protocol else 'UNKNOWN'
                    distribution[clean_protocol] = count
                
                return distribution
                
        except Exception as e:
            logging.error(f"Error getting protocol distribution: {e}")
            return {}
    
    def store_packet(self, packet_data: Dict[str, Any]) -> bool:
        """
        Store a captured packet in the database
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.get_session() as session:
                packet = NetworkPacket(
                    timestamp=datetime.fromisoformat(packet_data['timestamp'].replace('Z', '+00:00')) if isinstance(packet_data['timestamp'], str) else packet_data['timestamp'],
                    source_ip=packet_data.get('src_ip', 'Unknown'),
                    dest_ip=packet_data.get('dst_ip', 'Unknown'),
                    source_port=packet_data.get('src_port', 0),
                    dest_port=packet_data.get('dst_port', 0),
                    protocol=packet_data.get('protocol', 'Unknown'),
                    packet_size=packet_data.get('length', packet_data.get('packet_size', 0)),
                    tcp_flags=packet_data.get('flags', ''),
                    raw_data=json.dumps({
                        'anomaly_score': packet_data.get('anomaly_score', 0.0),
                        'packet_type': packet_data.get('packet_type', ''),
                        'raw_features': packet_data.get('raw_features', {})
                    })
                )
                
                session.add(packet)
                session.commit()
                return True
                
        except Exception as e:
            logging.error(f"Error storing packet: {e}")
            return False
    
    def store_anomaly(self, anomaly_data: Dict[str, Any]) -> bool:
        """
        Store an anomaly detection result in the database
        
        Args:
            anomaly_data: Dictionary containing anomaly information
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.get_session() as session:
                anomaly = AnomalyDetection(
                    timestamp=datetime.fromisoformat(anomaly_data['timestamp'].replace('Z', '+00:00')) if isinstance(anomaly_data['timestamp'], str) else anomaly_data['timestamp'],
                    source_ip=anomaly_data.get('source_ip', anomaly_data.get('src_ip', 'Unknown')),
                    dest_ip=anomaly_data.get('dest_ip', anomaly_data.get('dst_ip', 'Unknown')),
                    protocol=anomaly_data.get('protocol', 'Unknown'),
                    anomaly_score=anomaly_data.get('anomaly_score', 0.0),
                    severity=anomaly_data.get('severity', 'medium'),
                    description=anomaly_data.get('description', 'Anomaly detected'),
                    model_name=anomaly_data.get('model_name', 'packet_analyzer'),
                    is_anomaly=True,
                    features=json.dumps(anomaly_data.get('details', {}))
                )
                
                session.add(anomaly)
                session.commit()
                return True
                
        except Exception as e:
            logging.error(f"Error storing anomaly: {e}")
            return False
    
    def _flow_to_dict(self, flow: NetworkFlow) -> Dict[str, Any]:
        """Convert NetworkFlow object to dictionary"""
        return {
            'id': flow.id,
            'flow_id': flow.flow_id,
            'start_time': flow.start_time.isoformat() if flow.start_time else None,
            'end_time': flow.end_time.isoformat() if flow.end_time else None,
            'duration': flow.duration,
            'source_ip': flow.source_ip,
            'dest_ip': flow.dest_ip,
            'source_port': flow.source_port,
            'dest_port': flow.dest_port,
            'protocol': flow.protocol,
            'packet_count': flow.packet_count,
            'byte_count': flow.byte_count,
            'packets_per_second': flow.packets_per_second,
            'bytes_per_second': flow.bytes_per_second,
            'avg_packet_size': flow.avg_packet_size
        }
    
    def _anomaly_to_dict(self, anomaly: AnomalyDetection) -> Dict[str, Any]:
        """Convert AnomalyDetection object to dictionary"""
        return {
            'id': anomaly.id,
            'timestamp': anomaly.timestamp.isoformat() if anomaly.timestamp else None,
            'flow_id': anomaly.flow_id,
            'source_ip': anomaly.source_ip,
            'dest_ip': anomaly.dest_ip,
            'protocol': anomaly.protocol,
            'anomaly_score': anomaly.anomaly_score,
            'model_name': anomaly.model_name,
            'is_anomaly': anomaly.is_anomaly,
            'severity': anomaly.severity,
            'description': anomaly.description
        }

# Global database manager instance
db_manager = DatabaseManager()
