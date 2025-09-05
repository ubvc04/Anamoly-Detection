"""
Network Traffic Capture Module
Handles real-time network packet capture using Scapy with Npcap on Windows
"""

import logging
import threading
import time
import queue
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
import netifaces
import psutil
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from config.config import config
from database import db_manager

@dataclass
class PacketInfo:
    """Structured packet information"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    packet_size: int
    tcp_flags: Optional[str]
    interface: str
    flow_id: str
    payload_size: int
    ttl: Optional[int]
    window_size: Optional[int]
    raw_data: Dict[str, Any]

class NetworkInterfaceManager:
    """Manages network interfaces for packet capture"""
    
    def __init__(self):
        """Initialize interface manager"""
        self.interfaces = {}
        self.refresh_interfaces()
    
    def refresh_interfaces(self) -> None:
        """Refresh available network interfaces"""
        try:
            self.interfaces = {}
            
            # First try to get interfaces using Scapy (which uses Npcap on Windows)
            try:
                from scapy.arch.windows import get_windows_if_list
                scapy_interfaces = get_windows_if_list()
                
                for iface in scapy_interfaces:
                    interface_name = iface['name']
                    # Skip loopback and virtual interfaces for main monitoring
                    if any(skip_word in interface_name.lower() for skip_word in ['loopback', 'pseudo', 'teredo', 'isatap']):
                        continue
                    
                    self.interfaces[interface_name] = {
                        'name': interface_name,
                        'description': iface.get('description', ''),
                        'mac': iface.get('mac', ''),
                        'guid': iface.get('guid', ''),
                        'ips': iface.get('ips', []),
                        'is_up': True  # Assume up if listed by Scapy
                    }
                    
                logging.info(f"Found {len(self.interfaces)} network interfaces using Scapy/Npcap")
                
                # If we found interfaces, we're done
                if self.interfaces:
                    return
                    
            except ImportError:
                logging.warning("Scapy Windows interface detection not available")
            except Exception as e:
                logging.warning(f"Error using Scapy interface detection: {e}")
            
            # Fallback to netifaces
            for interface_name in netifaces.interfaces():
                interface_info = netifaces.ifaddresses(interface_name)
                
                # Skip loopback and virtual interfaces for main monitoring
                if any(skip_word in interface_name.lower() for skip_word in ['loopback', 'virtual', 'pseudo']):
                    continue
                
                # Get IPv4 and IPv6 addresses
                ipv4_addresses = []
                ipv6_addresses = []
                
                if netifaces.AF_INET in interface_info:
                    ipv4_addresses = [addr['addr'] for addr in interface_info[netifaces.AF_INET]]
                
                if netifaces.AF_INET6 in interface_info:
                    ipv6_addresses = [addr['addr'] for addr in interface_info[netifaces.AF_INET6]]
                
                # Only include interfaces with IP addresses
                if ipv4_addresses or ipv6_addresses:
                    self.interfaces[interface_name] = {
                        'name': interface_name,
                        'description': interface_name,
                        'ipv4_addresses': ipv4_addresses,
                        'ipv6_addresses': ipv6_addresses,
                        'is_up': self._is_interface_up(interface_name)
                    }
            
            # If still no interfaces, add a default one for testing
            if not self.interfaces:
                logging.warning("No network interfaces detected, adding default interface")
                self.interfaces['default'] = {
                    'name': 'default',
                    'description': 'Default network interface',
                    'ipv4_addresses': ['127.0.0.1'],
                    'ipv6_addresses': [],
                    'is_up': True
                }
            
            logging.info(f"Total interfaces available: {len(self.interfaces)}")
            for name, info in self.interfaces.items():
                logging.info(f"  - {name}: {info.get('description', 'No description')}")
            
        except Exception as e:
            logging.error(f"Error refreshing interfaces: {e}")
            # Ensure we have at least one interface for the system to work
            self.interfaces = {
                'default': {
                    'name': 'default',
                    'description': 'Default network interface',
                    'ipv4_addresses': ['127.0.0.1'],
                    'ipv6_addresses': [],
                    'is_up': True
                }
            }
    
    def _is_interface_up(self, interface_name: str) -> bool:
        """Check if interface is up and running"""
        try:
            stats = psutil.net_if_stats().get(interface_name)
            return stats.isup if stats else False
        except:
            return False
    
    def get_active_interfaces(self) -> List[str]:
        """Get list of active interface names"""
        return [name for name, info in self.interfaces.items() if info['is_up']]
    
    def get_interface_info(self, interface_name: str) -> Optional[Dict[str, Any]]:
        """Get information about specific interface"""
        return self.interfaces.get(interface_name)
    
    def get_all_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Get all interface information"""
        return self.interfaces.copy()

class FlowTracker:
    """Tracks network flows for analysis"""
    
    def __init__(self, flow_timeout: int = 60):
        """
        Initialize flow tracker
        
        Args:
            flow_timeout: Flow timeout in seconds
        """
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.lock = threading.Lock()
    
    def generate_flow_id(self, packet_info: PacketInfo) -> str:
        """
        Generate unique flow ID for packet
        
        Args:
            packet_info: Packet information
            
        Returns:
            Flow ID string
        """
        # Create bidirectional flow ID
        src_ip = packet_info.source_ip
        dst_ip = packet_info.dest_ip
        src_port = packet_info.source_port or 0
        dst_port = packet_info.dest_port or 0
        protocol = packet_info.protocol
        
        # Ensure consistent ordering for bidirectional flows
        if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
            src_ip, dst_ip = dst_ip, src_ip
            src_port, dst_port = dst_port, src_port
        
        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return hashlib.md5(flow_key.encode()).hexdigest()[:16]
    
    def update_flow(self, packet_info: PacketInfo) -> None:
        """
        Update flow statistics with new packet
        
        Args:
            packet_info: Packet information
        """
        with self.lock:
            flow_id = packet_info.flow_id
            
            if flow_id not in self.flows:
                # Create new flow
                self.flows[flow_id] = {
                    'flow_id': flow_id,
                    'start_time': packet_info.timestamp,
                    'last_seen': packet_info.timestamp,
                    'source_ip': packet_info.source_ip,
                    'dest_ip': packet_info.dest_ip,
                    'source_port': packet_info.source_port,
                    'dest_port': packet_info.dest_port,
                    'protocol': packet_info.protocol,
                    'packet_count': 0,
                    'byte_count': 0,
                    'packet_sizes': [],
                    'tcp_flags': set(),
                    'interfaces': set()
                }
            
            # Update flow statistics
            flow = self.flows[flow_id]
            flow['last_seen'] = packet_info.timestamp
            flow['packet_count'] += 1
            flow['byte_count'] += packet_info.packet_size
            flow['packet_sizes'].append(packet_info.packet_size)
            flow['interfaces'].add(packet_info.interface)
            
            if packet_info.tcp_flags:
                flow['tcp_flags'].add(packet_info.tcp_flags)
    
    def get_completed_flows(self) -> List[Dict[str, Any]]:
        """
        Get and remove completed flows
        
        Returns:
            List of completed flow dictionaries
        """
        completed_flows = []
        current_time = datetime.now()
        
        with self.lock:
            # Find expired flows
            expired_flow_ids = []
            for flow_id, flow in self.flows.items():
                time_diff = (current_time - flow['last_seen']).total_seconds()
                if time_diff > self.flow_timeout:
                    expired_flow_ids.append(flow_id)
            
            # Process expired flows
            for flow_id in expired_flow_ids:
                flow = self.flows.pop(flow_id)
                
                # Calculate flow statistics
                duration = (flow['last_seen'] - flow['start_time']).total_seconds()
                packet_sizes = flow['packet_sizes']
                
                flow_stats = {
                    'flow_id': flow['flow_id'],
                    'start_time': flow['start_time'],
                    'end_time': flow['last_seen'],
                    'duration': max(duration, 0.001),  # Avoid division by zero
                    'source_ip': flow['source_ip'],
                    'dest_ip': flow['dest_ip'],
                    'source_port': flow['source_port'],
                    'dest_port': flow['dest_port'],
                    'protocol': flow['protocol'],
                    'packet_count': flow['packet_count'],
                    'byte_count': flow['byte_count'],
                    'packets_per_second': flow['packet_count'] / max(duration, 0.001),
                    'bytes_per_second': flow['byte_count'] / max(duration, 0.001),
                    'avg_packet_size': sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
                    'std_packet_size': (sum((x - (sum(packet_sizes)/len(packet_sizes)))**2 for x in packet_sizes) / len(packet_sizes))**0.5 if len(packet_sizes) > 1 else 0,
                    'min_packet_size': min(packet_sizes) if packet_sizes else 0,
                    'max_packet_size': max(packet_sizes) if packet_sizes else 0,
                    'tcp_flags_count': {flag: 1 for flag in flow['tcp_flags']}
                }
                
                completed_flows.append(flow_stats)
        
        return completed_flows

class PacketCapture:
    """Main packet capture class"""
    
    def __init__(self):
        """Initialize packet capture"""
        self.interface_manager = NetworkInterfaceManager()
        self.flow_tracker = FlowTracker(config.get('network.analysis.flow_timeout', 60))
        self.packet_queue = queue.Queue(maxsize=10000)
        self.capture_threads = {}
        self.processing_thread = None
        self.running = False
        self.packet_callback = None
        self.flow_callback = None
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'flows_completed': 0,
            'capture_errors': 0,
            'start_time': None
        }
    
    def set_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Set callback for packet processing"""
        self.packet_callback = callback
    
    def set_flow_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Set callback for flow processing"""
        self.flow_callback = callback
    
    def start_capture(self, interfaces: Optional[List[str]] = None) -> None:
        """
        Start packet capture on specified interfaces
        
        Args:
            interfaces: List of interface names to capture on
        """
        if self.running:
            logging.warning("Packet capture is already running")
            return
        
        try:
            # Refresh interfaces
            self.interface_manager.refresh_interfaces()
            
            # Determine interfaces to capture on
            if interfaces is None:
                # Use configured interfaces or all active interfaces
                configured_interfaces = config.get('network.interfaces', [])
                if configured_interfaces:
                    capture_interfaces = configured_interfaces
                else:
                    capture_interfaces = self.interface_manager.get_active_interfaces()
            else:
                capture_interfaces = interfaces
            
            if not capture_interfaces:
                raise ValueError("No network interfaces available for capture")
            
            self.running = True
            self.stats['start_time'] = datetime.now()
            
            # Start capture threads for each interface
            for interface in capture_interfaces:
                if interface in self.interface_manager.get_all_interfaces():
                    thread = threading.Thread(
                        target=self._capture_interface,
                        args=(interface,),
                        daemon=True
                    )
                    thread.start()
                    self.capture_threads[interface] = thread
                    logging.info(f"Started capture on interface: {interface}")
            
            # Start packet processing thread
            self.processing_thread = threading.Thread(
                target=self._process_packets,
                daemon=True
            )
            self.processing_thread.start()
            
            # Start flow monitoring thread
            flow_thread = threading.Thread(
                target=self._monitor_flows,
                daemon=True
            )
            flow_thread.start()
            
            logging.info(f"Packet capture started on {len(capture_interfaces)} interfaces")
            
        except Exception as e:
            logging.error(f"Error starting packet capture: {e}")
            self.stop_capture()
            raise
    
    def stop_capture(self) -> None:
        """Stop packet capture"""
        self.running = False
        
        # Wait for threads to finish
        for interface, thread in self.capture_threads.items():
            try:
                thread.join(timeout=5)
                logging.info(f"Stopped capture on interface: {interface}")
            except:
                pass
        
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        self.capture_threads.clear()
        self.processing_thread = None
        
        logging.info("Packet capture stopped")
    
    def _capture_interface(self, interface: str) -> None:
        """
        Capture packets on specific interface
        
        Args:
            interface: Interface name
        """
        try:
            capture_filter = config.get('network.capture.filter', '')
            
            # Handle default interface case
            if interface == 'default':
                logging.info("Using default interface for packet capture")
                interface = None  # Let Scapy choose
            
            logging.info(f"Starting packet capture on interface: {interface or 'default'}")
            
            # Start packet capture with error handling
            try:
                sniff(
                    iface=interface,
                    prn=lambda pkt: self._packet_handler(pkt, interface or 'default'),
                    filter=capture_filter,
                    store=False,
                    stop_filter=lambda x: not self.running,
                    timeout=1  # Add timeout to prevent hanging
                )
            except PermissionError:
                logging.error(f"Permission denied for interface {interface}. Please run as administrator.")
                self.stats['capture_errors'] += 1
            except OSError as e:
                if "No such device exists" in str(e):
                    logging.error(f"Interface {interface} not found. Available interfaces: {list(self.interface_manager.get_all_interfaces().keys())}")
                else:
                    logging.error(f"OS error capturing on interface {interface}: {e}")
                self.stats['capture_errors'] += 1
            
        except Exception as e:
            logging.error(f"Error capturing on interface {interface}: {e}")
            self.stats['capture_errors'] += 1
    
    def _packet_handler(self, packet, interface: str) -> None:
        """
        Handle captured packet
        
        Args:
            packet: Scapy packet object
            interface: Interface name
        """
        try:
            packet_info = self._extract_packet_info(packet, interface)
            if packet_info:
                # Add to processing queue
                if not self.packet_queue.full():
                    self.packet_queue.put(packet_info, block=False)
                    self.stats['packets_captured'] += 1
                else:
                    logging.warning("Packet queue is full, dropping packet")
                    
        except Exception as e:
            logging.error(f"Error handling packet: {e}")
            self.stats['capture_errors'] += 1
    
    def _extract_packet_info(self, packet, interface: str) -> Optional[PacketInfo]:
        """
        Extract information from packet
        
        Args:
            packet: Scapy packet object
            interface: Interface name
            
        Returns:
            PacketInfo object or None
        """
        try:
            timestamp = datetime.now()
            
            # Initialize packet info
            source_ip = None
            dest_ip = None
            source_port = None
            dest_port = None
            protocol = "Unknown"
            tcp_flags = None
            ttl = None
            window_size = None
            payload_size = 0
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                protocol = ip_layer.proto
                ttl = ip_layer.ttl
                
                # Convert protocol number to name
                protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
                protocol = protocol_names.get(protocol, f"IP-{protocol}")
                
            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                source_ip = ipv6_layer.src
                dest_ip = ipv6_layer.dst
                protocol = f"IPv6-{ipv6_layer.nh}"
            
            # Extract transport layer information
            if TCP in packet:
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                protocol = "TCP"
                window_size = tcp_layer.window
                
                # Extract TCP flags
                flags = []
                if tcp_layer.flags.F: flags.append("FIN")
                if tcp_layer.flags.S: flags.append("SYN")
                if tcp_layer.flags.R: flags.append("RST")
                if tcp_layer.flags.P: flags.append("PSH")
                if tcp_layer.flags.A: flags.append("ACK")
                if tcp_layer.flags.U: flags.append("URG")
                tcp_flags = ",".join(flags)
                
                # Calculate payload size
                if Raw in packet:
                    payload_size = len(packet[Raw].load)
                    
            elif UDP in packet:
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                dest_port = udp_layer.dport
                protocol = "UDP"
                
                # Check for DNS
                if DNS in packet:
                    protocol = "DNS"
                    
                # Calculate payload size
                payload_size = len(udp_layer.payload) if udp_layer.payload else 0
                
            elif ICMP in packet:
                protocol = "ICMP"
                payload_size = len(packet[ICMP].payload) if packet[ICMP].payload else 0
            
            # Skip if no IP information
            if not source_ip or not dest_ip:
                return None
            
            # Create packet info
            packet_info = PacketInfo(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                packet_size=len(packet),
                tcp_flags=tcp_flags,
                interface=interface,
                flow_id="",  # Will be set later
                payload_size=payload_size,
                ttl=ttl,
                window_size=window_size,
                raw_data={
                    'packet_summary': str(packet.summary()),
                    'layer_count': len(packet.layers()),
                    'has_payload': Raw in packet
                }
            )
            
            # Generate flow ID
            packet_info.flow_id = self.flow_tracker.generate_flow_id(packet_info)
            
            return packet_info
            
        except Exception as e:
            logging.error(f"Error extracting packet info: {e}")
            return None
    
    def _process_packets(self) -> None:
        """Process packets from queue"""
        while self.running:
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1)
                
                # Update flow tracker
                self.flow_tracker.update_flow(packet_info)
                
                # Store packet in database
                packet_data = {
                    'timestamp': packet_info.timestamp,
                    'source_ip': packet_info.source_ip,
                    'dest_ip': packet_info.dest_ip,
                    'source_port': packet_info.source_port,
                    'dest_port': packet_info.dest_port,
                    'protocol': packet_info.protocol,
                    'packet_size': packet_info.packet_size,
                    'tcp_flags': packet_info.tcp_flags,
                    'flow_id': packet_info.flow_id,
                    'interface': packet_info.interface,
                    'raw_data': packet_info.raw_data
                }
                
                db_manager.insert_packet(packet_data)
                
                # Call packet callback if set
                if self.packet_callback:
                    self.packet_callback(packet_info)
                
                self.stats['packets_processed'] += 1
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
    
    def _monitor_flows(self) -> None:
        """Monitor and process completed flows"""
        while self.running:
            try:
                # Get completed flows
                completed_flows = self.flow_tracker.get_completed_flows()
                
                for flow in completed_flows:
                    # Store flow in database
                    db_manager.insert_flow(flow)
                    
                    # Call flow callback if set
                    if self.flow_callback:
                        self.flow_callback(flow)
                    
                    self.stats['flows_completed'] += 1
                
                # Sleep before next check
                time.sleep(5)
                
            except Exception as e:
                logging.error(f"Error monitoring flows: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics"""
        stats = self.stats.copy()
        stats['running'] = self.running
        stats['active_interfaces'] = list(self.capture_threads.keys())
        stats['queue_size'] = self.packet_queue.qsize()
        stats['active_flows'] = len(self.flow_tracker.flows)
        
        if stats['start_time']:
            runtime = (datetime.now() - stats['start_time']).total_seconds()
            stats['runtime_seconds'] = runtime
            stats['packets_per_second'] = stats['packets_captured'] / max(runtime, 1)
        
        return stats
    
    def get_interface_list(self) -> Dict[str, Dict[str, Any]]:
        """Get available network interfaces"""
        self.interface_manager.refresh_interfaces()
        return self.interface_manager.get_all_interfaces()

# Global packet capture instance
packet_capture = PacketCapture()
