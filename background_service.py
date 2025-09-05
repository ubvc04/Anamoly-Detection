"""
Background Service Module
Windows service for continuous network monitoring and anomaly detection
"""

import logging
import time
import threading
import sys
import os
import signal
from datetime import datetime, timedelta
from pathlib import Path
import win32serviceutil
import win32service
import win32event
import servicemanager
from config.config import config
from database import db_manager
from network_capture import packet_capture
from detector import detection_engine
from ml_model import ml_model_manager
from feature_extraction import feature_extractor

class NetworkAnomalyService(win32serviceutil.ServiceFramework):
    """Windows service for network anomaly detection"""
    
    _svc_name_ = config.get('service.name', 'NetworkAnomalyDetector')
    _svc_display_name_ = config.get('service.display_name', 'Network Anomaly Detection Service')
    _svc_description_ = config.get('service.description', 
                                  'Real-time network anomaly detection and monitoring service')
    
    def __init__(self, args):
        """Initialize service"""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        self.monitoring_thread = None
        self.training_thread = None
        self.cleanup_thread = None
        
        # Setup logging for service
        self._setup_service_logging()
        
    def _setup_service_logging(self) -> None:
        """Setup logging for Windows service"""
        try:
            # Create logs directory
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            # Configure logging
            log_config = config.get_log_config()
            logging.basicConfig(
                level=getattr(logging, config.get('logging.level', 'INFO')),
                format=config.get('logging.format', 
                                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
                handlers=[
                    logging.FileHandler(log_dir / "service.log"),
                    logging.StreamHandler()
                ]
            )
            
            # Log to Windows event log
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                servicemanager.PYS_SERVICE_STARTED,
                                (self._svc_name_, ''))
            
        except Exception as e:
            print(f"Error setting up service logging: {e}")
    
    def SvcStop(self):
        """Called when the service is asked to stop"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_running = False
        
        # Stop components
        self._stop_monitoring()
        
        logging.info("Network Anomaly Detection Service stopped")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STOPPED,
                            (self._svc_name_, ''))
    
    def SvcDoRun(self):
        """Called when the service is started"""
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))
        
        self.is_running = True
        self._start_monitoring()
        
        # Wait for stop event
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
    
    def _start_monitoring(self) -> None:
        """Start all monitoring components"""
        try:
            logging.info("Starting Network Anomaly Detection Service")
            
            # Initialize database
            self._initialize_database()
            
            # Load or train ML model
            self._initialize_ml_model()
            
            # Start detection engine
            detection_engine.start()
            
            # Setup packet capture callbacks
            packet_capture.set_packet_callback(self._on_packet_captured)
            packet_capture.set_flow_callback(self._on_flow_completed)
            
            # Start packet capture
            interfaces = config.get('network.interfaces', [])
            packet_capture.start_capture(interfaces)
            
            # Start background threads
            self._start_background_threads()
            
            logging.info("Network Anomaly Detection Service started successfully")
            
        except Exception as e:
            logging.error(f"Error starting monitoring: {e}")
            servicemanager.LogMsg(servicemanager.EVENTLOG_ERROR_TYPE,
                                servicemanager.PYS_SERVICE_STOPPED,
                                (self._svc_name_, f'Error: {str(e)}'))
            self.SvcStop()
    
    def _stop_monitoring(self) -> None:
        """Stop all monitoring components"""
        try:
            logging.info("Stopping monitoring components")
            
            # Stop packet capture
            packet_capture.stop_capture()
            
            # Stop detection engine
            detection_engine.stop()
            
            # Stop background threads
            self.is_running = False
            
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=10)
            
            if self.training_thread and self.training_thread.is_alive():
                self.training_thread.join(timeout=10)
            
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=10)
            
            logging.info("All monitoring components stopped")
            
        except Exception as e:
            logging.error(f"Error stopping monitoring: {e}")
    
    def _initialize_database(self) -> None:
        """Initialize database connection"""
        try:
            # Test database connection
            stats = db_manager.get_statistics()
            logging.info(f"Database initialized. Total records: {stats.get('total_packets', 0)} packets")
            
        except Exception as e:
            logging.error(f"Error initializing database: {e}")
            raise
    
    def _initialize_ml_model(self) -> None:
        """Initialize or load ML model"""
        try:
            # Try to load existing model
            if not ml_model_manager.load_latest_model():
                logging.info("No existing model found, training new model")
                
                # Train initial model
                training_result = ml_model_manager.train_model()
                
                if training_result.get('status') == 'success':
                    logging.info("Initial model training completed")
                else:
                    logging.warning("Initial model training failed, will retry later")
            else:
                logging.info("Loaded existing ML model")
            
        except Exception as e:
            logging.error(f"Error initializing ML model: {e}")
            # Don't fail service startup due to ML model issues
    
    def _start_background_threads(self) -> None:
        """Start background maintenance threads"""
        # Monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        # Training thread
        self.training_thread = threading.Thread(
            target=self._training_loop,
            daemon=True
        )
        self.training_thread.start()
        
        # Cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self.cleanup_thread.start()
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        last_stats_time = datetime.now()
        
        while self.is_running:
            try:
                # Log statistics every hour
                if (datetime.now() - last_stats_time).total_seconds() > 3600:
                    self._log_statistics()
                    last_stats_time = datetime.now()
                
                # Check system health
                self._check_system_health()
                
                # Sleep for a minute
                time.sleep(60)
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                time.sleep(60)
    
    def _training_loop(self) -> None:
        """Background model training loop"""
        while self.is_running:
            try:
                # Check if retraining is needed
                retrain_interval = config.get('machine_learning.training.retrain_interval', 86400)
                
                if ml_model_manager.last_training_time:
                    time_since_training = (datetime.now() - ml_model_manager.last_training_time).total_seconds()
                    
                    if time_since_training >= retrain_interval:
                        logging.info("Starting scheduled model retraining")
                        
                        training_result = ml_model_manager.train_model(retrain=True)
                        
                        if training_result.get('status') == 'success':
                            logging.info("Model retraining completed successfully")
                        else:
                            logging.error(f"Model retraining failed: {training_result}")
                
                # Sleep for an hour before checking again
                time.sleep(3600)
                
            except Exception as e:
                logging.error(f"Error in training loop: {e}")
                time.sleep(3600)
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop"""
        while self.is_running:
            try:
                # Cleanup old data daily
                logging.info("Starting data cleanup")
                db_manager.cleanup_old_data()
                
                # Sleep for 24 hours
                time.sleep(86400)
                
            except Exception as e:
                logging.error(f"Error in cleanup loop: {e}")
                time.sleep(86400)
    
    def _on_packet_captured(self, packet_info) -> None:
        """Callback for captured packets"""
        try:
            # Send to detection engine
            detection_engine.process_packet(packet_info)
            
        except Exception as e:
            logging.error(f"Error processing captured packet: {e}")
    
    def _on_flow_completed(self, flow_data) -> None:
        """Callback for completed flows"""
        try:
            # Send to detection engine
            detection_engine.process_flow(flow_data)
            
        except Exception as e:
            logging.error(f"Error processing completed flow: {e}")
    
    def _log_statistics(self) -> None:
        """Log system statistics"""
        try:
            # Capture statistics
            capture_stats = packet_capture.get_statistics()
            
            # Detection statistics
            detection_stats = detection_engine.get_statistics()
            
            # Database statistics
            db_stats = db_manager.get_statistics()
            
            # Log summary
            logging.info("=== SYSTEM STATISTICS ===")
            logging.info(f"Packets captured: {capture_stats.get('packets_captured', 0)}")
            logging.info(f"Flows completed: {capture_stats.get('flows_completed', 0)}")
            logging.info(f"Anomalies detected: {detection_stats.get('anomalies_detected', 0)}")
            logging.info(f"False positives filtered: {detection_stats.get('false_positives_filtered', 0)}")
            logging.info(f"Database records: {db_stats.get('total_packets', 0)} packets, "
                        f"{db_stats.get('total_flows', 0)} flows")
            logging.info("========================")
            
        except Exception as e:
            logging.error(f"Error logging statistics: {e}")
    
    def _check_system_health(self) -> None:
        """Check system health and restart components if needed"""
        try:
            # Check if packet capture is running
            if not packet_capture.running:
                logging.warning("Packet capture stopped, attempting restart")
                try:
                    interfaces = config.get('network.interfaces', [])
                    packet_capture.start_capture(interfaces)
                except Exception as e:
                    logging.error(f"Failed to restart packet capture: {e}")
            
            # Check if detection engine is running
            if not detection_engine.running:
                logging.warning("Detection engine stopped, attempting restart")
                try:
                    detection_engine.start()
                except Exception as e:
                    logging.error(f"Failed to restart detection engine: {e}")
            
            # Check memory usage
            import psutil
            process = psutil.Process()
            memory_percent = process.memory_percent()
            max_memory = config.get('performance.memory.max_usage', 80)
            
            if memory_percent > max_memory:
                logging.warning(f"High memory usage: {memory_percent:.1f}%")
                # Could implement memory cleanup here
            
        except Exception as e:
            logging.error(f"Error checking system health: {e}")

class ServiceManager:
    """Manages the Windows service installation and control"""
    
    @staticmethod
    def install_service():
        """Install the Windows service"""
        try:
            # Install service
            win32serviceutil.InstallService(
                NetworkAnomalyService,
                NetworkAnomalyService._svc_name_,
                NetworkAnomalyService._svc_display_name_,
                description=NetworkAnomalyService._svc_description_
            )
            
            print(f"Service '{NetworkAnomalyService._svc_display_name_}' installed successfully")
            
            # Configure service to start automatically
            if config.get('service.auto_start', True):
                ServiceManager.set_auto_start()
            
        except Exception as e:
            print(f"Error installing service: {e}")
    
    @staticmethod
    def remove_service():
        """Remove the Windows service"""
        try:
            win32serviceutil.RemoveService(NetworkAnomalyService._svc_name_)
            print(f"Service '{NetworkAnomalyService._svc_display_name_}' removed successfully")
            
        except Exception as e:
            print(f"Error removing service: {e}")
    
    @staticmethod
    def start_service():
        """Start the Windows service"""
        try:
            win32serviceutil.StartService(NetworkAnomalyService._svc_name_)
            print(f"Service '{NetworkAnomalyService._svc_display_name_}' started successfully")
            
        except Exception as e:
            print(f"Error starting service: {e}")
    
    @staticmethod
    def stop_service():
        """Stop the Windows service"""
        try:
            win32serviceutil.StopService(NetworkAnomalyService._svc_name_)
            print(f"Service '{NetworkAnomalyService._svc_display_name_}' stopped successfully")
            
        except Exception as e:
            print(f"Error stopping service: {e}")
    
    @staticmethod
    def restart_service():
        """Restart the Windows service"""
        try:
            ServiceManager.stop_service()
            time.sleep(2)
            ServiceManager.start_service()
            
        except Exception as e:
            print(f"Error restarting service: {e}")
    
    @staticmethod
    def get_service_status():
        """Get service status"""
        try:
            status = win32serviceutil.QueryServiceStatus(NetworkAnomalyService._svc_name_)
            status_map = {
                win32service.SERVICE_STOPPED: "Stopped",
                win32service.SERVICE_START_PENDING: "Start Pending",
                win32service.SERVICE_STOP_PENDING: "Stop Pending",
                win32service.SERVICE_RUNNING: "Running",
                win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
                win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
                win32service.SERVICE_PAUSED: "Paused"
            }
            
            return status_map.get(status[1], "Unknown")
            
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def set_auto_start():
        """Set service to start automatically"""
        try:
            import win32api
            import win32con
            
            # Open service manager
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            
            # Open service
            service = win32service.OpenService(
                scm, 
                NetworkAnomalyService._svc_name_, 
                win32service.SERVICE_ALL_ACCESS
            )
            
            # Change service configuration
            win32service.ChangeServiceConfig(
                service,
                win32service.SERVICE_NO_CHANGE,
                win32service.SERVICE_AUTO_START,  # Auto start
                win32service.SERVICE_NO_CHANGE,
                None, None, None, None, None, None, None
            )
            
            # Close handles
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)
            
            print("Service configured for automatic startup")
            
        except Exception as e:
            print(f"Error setting auto start: {e}")

class StandaloneRunner:
    """Run the service in standalone mode for development/testing"""
    
    def __init__(self):
        """Initialize standalone runner"""
        self.running = False
        self.service_core = None
        
    def start(self):
        """Start in standalone mode"""
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            # Create service core (without Windows service wrapper)
            print("Starting Network Anomaly Detection in standalone mode...")
            
            # Initialize components directly
            self._initialize_components()
            
            print("Network Anomaly Detection started successfully")
            print("Press Ctrl+C to stop")
            
            # Main loop
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error in standalone mode: {e}")
            logging.error(f"Error in standalone mode: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop standalone mode"""
        if not self.running:
            return
            
        print("\nStopping Network Anomaly Detection...")
        self.running = False
        
        try:
            # Stop components
            if detection_engine.running:
                detection_engine.stop()
                
            if packet_capture.running:
                packet_capture.stop_capture()
                
            print("Network Anomaly Detection stopped")
            
        except Exception as e:
            print(f"Error stopping: {e}")
            logging.error(f"Error stopping: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False
    
    def _initialize_components(self):
        """Initialize all components"""
        # Setup logging
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, config.get('logging.level', 'INFO')),
            format=config.get('logging.format'),
            handlers=[
                logging.FileHandler(log_dir / "standalone.log"),
                logging.StreamHandler()
            ]
        )
        
        # Initialize database
        db_stats = db_manager.get_statistics()
        logging.info(f"Database initialized. Records: {db_stats}")
        
        # Initialize ML model
        if not ml_model_manager.load_latest_model():
            logging.info("No existing model found, training new model")
            training_result = ml_model_manager.train_model()
            if training_result.get('status') != 'success':
                logging.warning("Model training failed, will retry later")
        
        # Start detection engine
        detection_engine.start()
        
        # Setup callbacks
        packet_capture.set_packet_callback(detection_engine.process_packet)
        packet_capture.set_flow_callback(detection_engine.process_flow)
        
        # Start packet capture
        interfaces = config.get('network.interfaces', [])
        packet_capture.start_capture(interfaces)

def main():
    """Main entry point for service management"""
    if len(sys.argv) == 1:
        # No arguments - try to start as service
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(NetworkAnomalyService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception:
            # If service start fails, run in standalone mode
            print("Failed to start as Windows service, running in standalone mode")
            runner = StandaloneRunner()
            runner.start()
    else:
        # Handle command line arguments
        command = sys.argv[1].lower()
        
        if command == 'install':
            ServiceManager.install_service()
        elif command == 'remove':
            ServiceManager.remove_service()
        elif command == 'start':
            ServiceManager.start_service()
        elif command == 'stop':
            ServiceManager.stop_service()
        elif command == 'restart':
            ServiceManager.restart_service()
        elif command == 'status':
            status = ServiceManager.get_service_status()
            print(f"Service status: {status}")
        elif command == 'standalone':
            runner = StandaloneRunner()
            runner.start()
        else:
            print("Usage:")
            print("  python background_service.py install   - Install Windows service")
            print("  python background_service.py remove    - Remove Windows service")
            print("  python background_service.py start     - Start service")
            print("  python background_service.py stop      - Stop service")
            print("  python background_service.py restart   - Restart service")
            print("  python background_service.py status    - Show service status")
            print("  python background_service.py standalone - Run in standalone mode")

if __name__ == '__main__':
    main()
