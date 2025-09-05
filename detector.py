"""
Real-time Detection Engine
Implements live anomaly detection with multi-model ensemble and alert system
"""

import logging
import threading
import time
import queue
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple
from collections import deque, defaultdict
from dataclasses import dataclass
from enum import Enum
import numpy as np
from config.config import config
from database import db_manager
from feature_extraction import feature_extractor, NetworkFeatures
from ml_model import ml_model_manager
from network_capture import PacketInfo

class SeverityLevel(Enum):
    """Anomaly severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AnomalyAlert:
    """Anomaly alert information"""
    id: str
    timestamp: datetime
    flow_id: str
    source_ip: str
    dest_ip: str
    dest_port: Optional[int]
    protocol: str
    severity: SeverityLevel
    anomaly_score: float
    model_name: str
    description: str
    features: Dict[str, float]
    raw_data: Dict[str, Any]

class AlertManager:
    """Manages anomaly alerts and notifications"""
    
    def __init__(self):
        """Initialize alert manager"""
        self.alerts = deque(maxlen=1000)  # Keep last 1000 alerts
        self.alert_callbacks = []
        self.alert_cooldown = {}  # Track cooldown periods
        self.alert_count = defaultdict(int)
        self.lock = threading.Lock()
    
    def add_alert_callback(self, callback: Callable[[AnomalyAlert], None]) -> None:
        """
        Add callback for alert notifications
        
        Args:
            callback: Function to call when alert is generated
        """
        self.alert_callbacks.append(callback)
    
    def create_alert(self, flow_id: str, source_ip: str, dest_ip: str,
                    dest_port: Optional[int], protocol: str, anomaly_score: float,
                    model_name: str, features: Dict[str, float],
                    raw_data: Dict[str, Any] = None) -> Optional[AnomalyAlert]:
        """
        Create anomaly alert
        
        Args:
            flow_id: Flow identifier
            source_ip: Source IP address
            dest_ip: Destination IP address
            dest_port: Destination port
            protocol: Protocol
            anomaly_score: Anomaly score (0-1)
            model_name: Model that detected anomaly
            features: Feature values
            raw_data: Additional raw data
            
        Returns:
            AnomalyAlert object or None if alert was filtered
        """
        try:
            # Determine severity based on score
            severity = self._calculate_severity(anomaly_score, features)
            
            # Check if alert should be suppressed due to cooldown
            if self._is_in_cooldown(source_ip, dest_ip, severity):
                return None
            
            # Check minimum severity threshold
            min_severity = config.get('detection.alerts.min_severity', 'medium')
            severity_order = ['low', 'medium', 'high', 'critical']
            
            if severity_order.index(severity.value) < severity_order.index(min_severity):
                return None
            
            # Generate alert ID
            alert_id = f"{int(datetime.now().timestamp())}_{flow_id[:8]}"
            
            # Create alert
            alert = AnomalyAlert(
                id=alert_id,
                timestamp=datetime.now(),
                flow_id=flow_id,
                source_ip=source_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=protocol,
                severity=severity,
                anomaly_score=anomaly_score,
                model_name=model_name,
                description=self._generate_description(severity, features, raw_data),
                features=features,
                raw_data=raw_data or {}
            )
            
            # Add to alerts list
            with self.lock:
                self.alerts.append(alert)
                self.alert_count[severity.value] += 1
                
                # Set cooldown
                cooldown_key = f"{source_ip}:{dest_ip}:{severity.value}"
                cooldown_duration = config.get('detection.alerts.cooldown', 300)
                self.alert_cooldown[cooldown_key] = datetime.now() + timedelta(seconds=cooldown_duration)
            
            # Store in database
            alert_data = {
                'timestamp': alert.timestamp,
                'flow_id': alert.flow_id,
                'source_ip': alert.source_ip,
                'dest_ip': alert.dest_ip,
                'protocol': alert.protocol,
                'anomaly_score': alert.anomaly_score,
                'model_name': alert.model_name,
                'is_anomaly': True,
                'severity': alert.severity.value,
                'description': alert.description,
                'features': alert.features
            }
            db_manager.insert_anomaly(alert_data)
            
            # Trigger callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logging.error(f"Error in alert callback: {e}")
            
            logging.warning(f"ANOMALY DETECTED: {alert.severity.value.upper()} - "
                          f"{alert.source_ip} -> {alert.dest_ip}:{alert.dest_port} "
                          f"(Score: {alert.anomaly_score:.3f})")
            
            return alert
            
        except Exception as e:
            logging.error(f"Error creating alert: {e}")
            return None
    
    def _calculate_severity(self, anomaly_score: float, features: Dict[str, float]) -> SeverityLevel:
        """Calculate severity level based on score and features"""
        # Base severity on anomaly score
        if anomaly_score >= 0.9:
            base_severity = SeverityLevel.CRITICAL
        elif anomaly_score >= 0.7:
            base_severity = SeverityLevel.HIGH
        elif anomaly_score >= 0.5:
            base_severity = SeverityLevel.MEDIUM
        else:
            base_severity = SeverityLevel.LOW
        
        # Adjust based on specific features
        severity_modifiers = 0
        
        # Check for suspicious patterns
        if features.get('is_suspicious_port', 0) > 0:
            severity_modifiers += 1
        
        if features.get('port_scan_indicator', 0) > 0:
            severity_modifiers += 2
        
        if features.get('connection_failed', 0) > 0:
            severity_modifiers += 1
        
        if features.get('is_outbound', 0) > 0 and features.get('is_night_time', 0) > 0:
            severity_modifiers += 1
        
        # Apply modifiers
        severity_levels = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        current_index = severity_levels.index(base_severity)
        new_index = min(current_index + severity_modifiers, len(severity_levels) - 1)
        
        return severity_levels[new_index]
    
    def _is_in_cooldown(self, source_ip: str, dest_ip: str, severity: SeverityLevel) -> bool:
        """Check if alert is in cooldown period"""
        with self.lock:
            cooldown_key = f"{source_ip}:{dest_ip}:{severity.value}"
            cooldown_time = self.alert_cooldown.get(cooldown_key)
            
            if cooldown_time and datetime.now() < cooldown_time:
                return True
            
            return False
    
    def _generate_description(self, severity: SeverityLevel, features: Dict[str, float],
                            raw_data: Dict[str, Any]) -> str:
        """Generate human-readable description of the anomaly"""
        descriptions = []
        
        # Protocol-based descriptions
        protocol = raw_data.get('protocol', 'Unknown')
        if protocol in ['TCP', 'UDP']:
            descriptions.append(f"Unusual {protocol} traffic pattern detected")
        
        # Feature-based descriptions
        if features.get('is_suspicious_port', 0) > 0:
            descriptions.append("Connection to suspicious port")
        
        if features.get('port_scan_indicator', 0) > 0:
            descriptions.append("Potential port scanning activity")
        
        if features.get('high_packet_rate', 0) > 0:
            descriptions.append("Unusually high packet rate")
        
        if features.get('high_byte_rate', 0) > 0:
            descriptions.append("Unusually high data transfer rate")
        
        if features.get('connection_failed', 0) > 0:
            descriptions.append("Failed connection attempt")
        
        if features.get('is_outbound', 0) > 0 and features.get('is_night_time', 0) > 0:
            descriptions.append("Outbound connection during off-hours")
        
        if features.get('unique_dest_ports', 0) > 10:
            descriptions.append("Connection to many different ports")
        
        # Default description
        if not descriptions:
            descriptions.append(f"Anomalous network behavior ({severity.value} severity)")
        
        return "; ".join(descriptions)
    
    def get_recent_alerts(self, hours: int = 24) -> List[AnomalyAlert]:
        """Get recent alerts"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            return [alert for alert in self.alerts if alert.timestamp >= cutoff_time]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        with self.lock:
            total_alerts = len(self.alerts)
            
            # Count by severity
            severity_counts = {
                'low': self.alert_count['low'],
                'medium': self.alert_count['medium'],
                'high': self.alert_count['high'],
                'critical': self.alert_count['critical']
            }
            
            # Recent alerts (last hour)
            recent_cutoff = datetime.now() - timedelta(hours=1)
            recent_alerts = [alert for alert in self.alerts if alert.timestamp >= recent_cutoff]
            
            return {
                'total_alerts': total_alerts,
                'severity_counts': severity_counts,
                'recent_alerts_count': len(recent_alerts),
                'active_cooldowns': len([k for k, v in self.alert_cooldown.items() 
                                       if datetime.now() < v])
            }

class FalsePositiveFilter:
    """Filters false positive alerts based on patterns and user feedback"""
    
    def __init__(self):
        """Initialize false positive filter"""
        self.whitelist_ips = set()
        self.whitelist_ports = set()
        self.known_patterns = set()
        self.user_feedback = {}  # Track user-marked false positives
        
        # Load default whitelists
        self._load_default_whitelists()
    
    def _load_default_whitelists(self) -> None:
        """Load default IP and port whitelists"""
        # Common legitimate destinations
        self.whitelist_ips.update([
            '8.8.8.8', '8.8.4.4',  # Google DNS
            '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
            '208.67.222.222', '208.67.220.220'  # OpenDNS
        ])
        
        # Common legitimate ports
        self.whitelist_ports.update([
            53, 80, 443, 993, 995, 587, 465  # DNS, HTTP, HTTPS, IMAP, POP3, SMTP
        ])
    
    def is_false_positive(self, alert: AnomalyAlert) -> bool:
        """
        Check if alert is likely a false positive
        
        Args:
            alert: Anomaly alert to check
            
        Returns:
            True if likely false positive
        """
        # Check whitelists
        if alert.dest_ip in self.whitelist_ips:
            return True
        
        if alert.dest_port in self.whitelist_ports:
            return True
        
        # Check for known safe patterns
        pattern = f"{alert.source_ip}:{alert.dest_ip}:{alert.dest_port}"
        if pattern in self.known_patterns:
            return True
        
        # Check user feedback
        flow_pattern = f"{alert.source_ip}:{alert.dest_ip}:{alert.protocol}"
        if self.user_feedback.get(flow_pattern) == 'false_positive':
            return True
        
        # Additional heuristics
        features = alert.features
        
        # Very low scores might be false positives
        if alert.anomaly_score < 0.3:
            return True
        
        # Normal business hours with standard protocols
        if (features.get('is_business_hours', 0) > 0 and 
            features.get('is_http', 0) > 0 and 
            alert.anomaly_score < 0.6):
            return True
        
        return False
    
    def add_user_feedback(self, alert: AnomalyAlert, is_false_positive: bool) -> None:
        """
        Add user feedback about alert
        
        Args:
            alert: Alert to provide feedback on
            is_false_positive: Whether user marked as false positive
        """
        flow_pattern = f"{alert.source_ip}:{alert.dest_ip}:{alert.protocol}"
        self.user_feedback[flow_pattern] = 'false_positive' if is_false_positive else 'true_positive'
        
        # Update database
        try:
            # This would update the database with user feedback
            # Implementation depends on your database schema
            pass
        except Exception as e:
            logging.error(f"Error saving user feedback: {e}")

class StreamingDetector:
    """Main streaming anomaly detection engine"""
    
    def __init__(self):
        """Initialize streaming detector"""
        self.alert_manager = AlertManager()
        self.fp_filter = FalsePositiveFilter()
        self.processing_queue = queue.Queue(maxsize=10000)
        self.batch_buffer = []
        self.processing_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'flows_processed': 0,
            'anomalies_detected': 0,
            'false_positives_filtered': 0,
            'processing_errors': 0,
            'start_time': None
        }
        
        # Configuration
        self.batch_size = config.get('detection.realtime.batch_size', 100)
        self.processing_interval = config.get('detection.realtime.processing_interval', 5)
    
    def start(self) -> None:
        """Start the detection engine"""
        if self.running:
            logging.warning("Detection engine is already running")
            return
        
        try:
            # Ensure ML model is loaded
            if not ml_model_manager.current_model:
                if not ml_model_manager.load_latest_model():
                    logging.warning("No trained model available for detection")
                    # Train a model if none exists
                    training_result = ml_model_manager.train_model()
                    if training_result.get('status') != 'success':
                        raise Exception("Failed to train initial model")
            
            self.running = True
            self.stats['start_time'] = datetime.now()
            
            # Start processing thread
            self.processing_thread = threading.Thread(
                target=self._processing_loop,
                daemon=True
            )
            self.processing_thread.start()
            
            logging.info("Real-time anomaly detection engine started")
            
        except Exception as e:
            logging.error(f"Error starting detection engine: {e}")
            self.running = False
            raise
    
    def stop(self) -> None:
        """Stop the detection engine"""
        self.running = False
        
        if self.processing_thread:
            self.processing_thread.join(timeout=10)
            self.processing_thread = None
        
        logging.info("Real-time anomaly detection engine stopped")
    
    def process_packet(self, packet_info: PacketInfo) -> None:
        """
        Process individual packet for anomaly detection
        
        Args:
            packet_info: Packet information
        """
        try:
            if not self.running:
                return
            
            # Add to processing queue
            if not self.processing_queue.full():
                self.processing_queue.put(('packet', packet_info))
            else:
                logging.warning("Processing queue is full, dropping packet")
            
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            self.stats['processing_errors'] += 1
    
    def process_flow(self, flow_data: Dict[str, Any]) -> None:
        """
        Process network flow for anomaly detection
        
        Args:
            flow_data: Flow information dictionary
        """
        try:
            if not self.running:
                return
            
            # Add to processing queue
            if not self.processing_queue.full():
                self.processing_queue.put(('flow', flow_data))
            else:
                logging.warning("Processing queue is full, dropping flow")
            
        except Exception as e:
            logging.error(f"Error processing flow: {e}")
            self.stats['processing_errors'] += 1
    
    def _processing_loop(self) -> None:
        """Main processing loop"""
        while self.running:
            try:
                # Process items from queue
                batch_items = []
                
                # Collect batch
                start_time = time.time()
                while (len(batch_items) < self.batch_size and 
                       (time.time() - start_time) < self.processing_interval):
                    try:
                        item = self.processing_queue.get(timeout=1)
                        batch_items.append(item)
                    except queue.Empty:
                        break
                
                # Process batch
                if batch_items:
                    self._process_batch(batch_items)
                
                # Short sleep to prevent busy waiting
                time.sleep(0.1)
                
            except Exception as e:
                logging.error(f"Error in processing loop: {e}")
                self.stats['processing_errors'] += 1
    
    def _process_batch(self, batch_items: List[Tuple[str, Any]]) -> None:
        """
        Process batch of items
        
        Args:
            batch_items: List of (type, data) tuples
        """
        try:
            for item_type, item_data in batch_items:
                if item_type == 'packet':
                    self._process_single_packet(item_data)
                elif item_type == 'flow':
                    self._process_single_flow(item_data)
                
        except Exception as e:
            logging.error(f"Error processing batch: {e}")
            self.stats['processing_errors'] += 1
    
    def _process_single_packet(self, packet_info: PacketInfo) -> None:
        """Process single packet"""
        try:
            # Extract features
            features = feature_extractor.extract_packet_features(packet_info)
            
            if features:
                self._detect_anomaly(features)
                self.stats['packets_processed'] += 1
            
        except Exception as e:
            logging.error(f"Error processing single packet: {e}")
            self.stats['processing_errors'] += 1
    
    def _process_single_flow(self, flow_data: Dict[str, Any]) -> None:
        """Process single flow"""
        try:
            # Extract features
            features = feature_extractor.extract_flow_features(flow_data)
            
            if features:
                self._detect_anomaly(features)
                self.stats['flows_processed'] += 1
            
        except Exception as e:
            logging.error(f"Error processing single flow: {e}")
            self.stats['processing_errors'] += 1
    
    def _detect_anomaly(self, features: NetworkFeatures) -> None:
        """
        Perform anomaly detection on features
        
        Args:
            features: Extracted network features
        """
        try:
            # Convert features to numpy array
            feature_vector = feature_extractor.get_feature_vector(features)
            
            if len(feature_vector) == 0:
                return
            
            # Predict anomaly
            prediction_result = ml_model_manager.predict_anomaly(feature_vector)
            
            if 'error' in prediction_result:
                logging.error(f"Prediction error: {prediction_result['error']}")
                return
            
            # Check if anomaly detected
            if prediction_result.get('is_anomaly', False):
                # Create alert
                alert = self.alert_manager.create_alert(
                    flow_id=features.flow_id,
                    source_ip=features.source_ip,
                    dest_ip=features.dest_ip,
                    dest_port=features.features.get('dest_port'),
                    protocol=features.protocol,
                    anomaly_score=prediction_result.get('anomaly_score', 0.0),
                    model_name='ensemble',
                    features=features.features,
                    raw_data={
                        'timestamp': features.timestamp.isoformat(),
                        'individual_scores': prediction_result.get('individual_scores', {}),
                        'individual_predictions': prediction_result.get('individual_predictions', {})
                    }
                )
                
                if alert:
                    # Check for false positive
                    if self.fp_filter.is_false_positive(alert):
                        self.stats['false_positives_filtered'] += 1
                        logging.debug(f"Filtered false positive: {alert.id}")
                    else:
                        self.stats['anomalies_detected'] += 1
                        
                        # Save features to database for future training
                        feature_extractor.save_features_to_database(features)
            
        except Exception as e:
            logging.error(f"Error in anomaly detection: {e}")
            self.stats['processing_errors'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection engine statistics"""
        stats = self.stats.copy()
        stats['running'] = self.running
        stats['queue_size'] = self.processing_queue.qsize()
        stats['batch_buffer_size'] = len(self.batch_buffer)
        
        # Add alert statistics
        stats['alert_stats'] = self.alert_manager.get_alert_statistics()
        
        # Calculate rates
        if stats['start_time']:
            runtime = (datetime.now() - stats['start_time']).total_seconds()
            stats['runtime_seconds'] = runtime
            stats['packets_per_second'] = stats['packets_processed'] / max(runtime, 1)
            stats['flows_per_second'] = stats['flows_processed'] / max(runtime, 1)
        
        return stats
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent alerts as dictionaries"""
        alerts = self.alert_manager.get_recent_alerts(hours)
        
        return [
            {
                'id': alert.id,
                'timestamp': alert.timestamp.isoformat(),
                'flow_id': alert.flow_id,
                'source_ip': alert.source_ip,
                'dest_ip': alert.dest_ip,
                'dest_port': alert.dest_port,
                'protocol': alert.protocol,
                'severity': alert.severity.value,
                'anomaly_score': alert.anomaly_score,
                'model_name': alert.model_name,
                'description': alert.description
            }
            for alert in alerts
        ]
    
    def add_alert_callback(self, callback: Callable[[AnomalyAlert], None]) -> None:
        """Add callback for alert notifications"""
        self.alert_manager.add_alert_callback(callback)
    
    def mark_false_positive(self, alert_id: str) -> bool:
        """
        Mark an alert as false positive
        
        Args:
            alert_id: Alert ID
            
        Returns:
            True if successful
        """
        try:
            # Find alert
            alert = None
            with self.alert_manager.lock:
                for a in self.alert_manager.alerts:
                    if a.id == alert_id:
                        alert = a
                        break
            
            if alert:
                self.fp_filter.add_user_feedback(alert, True)
                self.stats['false_positives_filtered'] += 1
                logging.info(f"Marked alert {alert_id} as false positive")
                return True
            else:
                logging.warning(f"Alert {alert_id} not found")
                return False
                
        except Exception as e:
            logging.error(f"Error marking false positive: {e}")
            return False

# Global detection engine instance
detection_engine = StreamingDetector()
