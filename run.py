import os
import sys
import threading
import time
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from config.config import ConfigManager
from database import DatabaseManager
from network_capture import PacketCapture
from detector import StreamingDetector
from background_service import ServiceManager
from app import create_app
import logging
import logging.config

class NetworkAnomalySystem:
    """Main system orchestrator for the network anomaly detection system."""
    
    def __init__(self, config_path=None):
        """
        Initialize the network anomaly detection system.
        
        Args:
            config_path: Optional path to configuration file
        """
        # Initialize configuration
        if config_path:
            self.config = ConfigManager(config_path)
        else:
            self.config = ConfigManager()
        
        # Initialize components
        self.db_manager = None
        self.packet_capture = None
        self.detector = None
        self.web_app = None
        
        # Control flags
        self.running = False
        self.capture_thread = None
        self.detection_thread = None
        self.web_thread = None
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
    
    def setup_logging(self):
        """Configure logging for the application."""
        # Get log configuration from config manager and apply it
        log_config = self.config.get_log_config()
        logging.config.dictConfig(log_config)
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Network Anomaly Detection System logging initialized")
    
    def initialize_components(self):
        """Initialize all system components."""
        try:
            self.logger.info("Initializing system components...")
            
            # Initialize database
            self.db_manager = DatabaseManager()
            self.logger.info("Database initialized")
            
            # Initialize packet capture
            self.packet_capture = PacketCapture()
            self.logger.info("Packet capture initialized")
            
            # Initialize anomaly detector
            self.detector = StreamingDetector()
            self.logger.info("Anomaly detector initialized")
            
            # Initialize web application
            self.web_app = create_app()
            self.logger.info("Web application initialized")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            return False
    
    def start_capture(self):
        """Start packet capture in a separate thread."""
        def capture_worker():
            try:
                self.logger.info("Starting packet capture...")
                self.packet_capture.start_capture()
            except Exception as e:
                self.logger.error(f"Packet capture error: {e}")
        
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
            self.capture_thread.start()
            self.logger.info("Packet capture thread started")
    
    def start_detection(self):
        """Start anomaly detection in a separate thread."""
        def detection_worker():
            try:
                self.logger.info("Starting anomaly detection...")
                self.detector.start_detection()
            except Exception as e:
                self.logger.error(f"Anomaly detection error: {e}")
        
        if not self.detection_thread or not self.detection_thread.is_alive():
            self.detection_thread = threading.Thread(target=detection_worker, daemon=True)
            self.detection_thread.start()
            self.logger.info("Anomaly detection thread started")
    
    def start_web_server(self):
        """Start the web server in a separate thread."""
        def web_worker():
            try:
                self.logger.info("Starting web server...")
                web_config = self.config.get('web', {})
                host = web_config.get('host', '127.0.0.1')
                port = web_config.get('port', 5000)
                debug = web_config.get('debug', False)
                
                self.web_app.run(host=host, port=port, debug=debug, threaded=True)
            except Exception as e:
                self.logger.error(f"Web server error: {e}")
        
        if not self.web_thread or not self.web_thread.is_alive():
            self.web_thread = threading.Thread(target=web_worker, daemon=True)
            self.web_thread.start()
            self.logger.info(f"Web server thread started")
    
    def start(self, mode='full'):
        """
        Start the system.
        
        Args:
            mode: 'full' for all components, 'capture' for capture only, 
                  'detection' for detection only, 'web' for web only
        """
        if not self.initialize_components():
            self.logger.error("Failed to initialize components")
            return False
        
        self.running = True
        self.logger.info(f"Starting system in {mode} mode...")
        
        try:
            if mode in ['full', 'capture']:
                self.start_capture()
            
            if mode in ['full', 'detection']:
                self.start_detection()
            
            if mode in ['full', 'web']:
                self.start_web_server()
            
            self.logger.info("System started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start system: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop all system components."""
        self.logger.info("Stopping system...")
        self.running = False
        
        try:
            # Stop packet capture
            if self.packet_capture:
                self.packet_capture.stop_capture()
                self.logger.info("Packet capture stopped")
            
            # Stop detection
            if self.detector:
                self.detector.stop_detection()
                self.logger.info("Anomaly detection stopped")
            
            # Close database connections
            if self.db_manager:
                self.db_manager.close()
                self.logger.info("Database connections closed")
            
            self.logger.info("System stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping system: {e}")
    
    def status(self):
        """Get system status information."""
        status = {
            'running': self.running,
            'components': {
                'database': self.db_manager is not None,
                'capture': self.packet_capture is not None and 
                          (self.capture_thread and self.capture_thread.is_alive()),
                'detection': self.detector is not None and 
                           (self.detection_thread and self.detection_thread.is_alive()),
                'web': self.web_app is not None and 
                      (self.web_thread and self.web_thread.is_alive())
            }
        }
        
        if self.packet_capture:
            status['capture_stats'] = self.packet_capture.get_statistics()
        
        if self.detector:
            status['detection_stats'] = self.detector.get_statistics()
        
        return status
    
    def run_forever(self):
        """Run the system indefinitely."""
        if not self.start():
            return False
        
        try:
            while self.running:
                time.sleep(1)
                
                # Check thread health
                if self.capture_thread and not self.capture_thread.is_alive():
                    self.logger.warning("Capture thread died, restarting...")
                    self.start_capture()
                
                if self.detection_thread and not self.detection_thread.is_alive():
                    self.logger.warning("Detection thread died, restarting...")
                    self.start_detection()
                
                if self.web_thread and not self.web_thread.is_alive():
                    self.logger.warning("Web thread died, restarting...")
                    self.start_web_server()
        
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            self.stop()
        
        return True

def main():
    """Main entry point for the application."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Anomaly Detection System')
    parser.add_argument('--config', '-c', type=str, 
                       help='Path to configuration file')
    parser.add_argument('--mode', '-m', type=str, default='full',
                       choices=['full', 'capture', 'detection', 'web'],
                       help='System mode (default: full)')
    parser.add_argument('--service', '-s', action='store_true',
                       help='Run as Windows service')
    parser.add_argument('--daemon', '-d', action='store_true',
                       help='Run in daemon mode')
    parser.add_argument('--status', action='store_true',
                       help='Show system status')
    parser.add_argument('--stop', action='store_true',
                       help='Stop running service')
    
    args = parser.parse_args()
    
    # Handle service management
    if args.service or args.stop:
        service_manager = ServiceManager()
        
        if args.stop:
            success = service_manager.stop_service()
            if success:
                print("Service stopped successfully")
                return 0
            else:
                print("Failed to stop service")
                return 1
        
        if args.service:
            success = service_manager.start_service()
            if success:
                print("Service started successfully")
                return 0
            else:
                print("Failed to start service")
                return 1
    
    # Initialize system
    system = NetworkAnomalySystem(args.config)
    
    # Handle status request
    if args.status:
        status = system.status()
        print(f"System Status:")
        print(f"  Running: {status['running']}")
        print(f"  Components:")
        for component, status_val in status['components'].items():
            print(f"    {component.title()}: {'✓' if status_val else '✗'}")
        
        if 'capture_stats' in status:
            stats = status['capture_stats']
            print(f"  Capture Statistics:")
            print(f"    Packets: {stats.get('packets_captured', 0)}")
            print(f"    Flows: {stats.get('flows_completed', 0)}")
        
        if 'detection_stats' in status:
            stats = status['detection_stats']
            print(f"  Detection Statistics:")
            print(f"    Anomalies: {stats.get('anomalies_detected', 0)}")
        
        return 0
    
    # Start system
    print(f"Starting Network Anomaly Detection System in {args.mode} mode...")
    print("Press Ctrl+C to stop")
    
    try:
        if args.daemon:
            success = system.run_forever()
        else:
            success = system.start(args.mode)
            if success:
                # Keep main thread alive
                while system.running:
                    time.sleep(1)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nShutting down...")
        system.stop()
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    exit(main())
