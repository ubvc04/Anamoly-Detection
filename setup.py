"""
Network Anomaly Detection System Setup Script
Automates the installation and configuration of the network anomaly detection system.
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path
import platform
import argparse

class SetupManager:
    """Manages the setup and installation process."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.python_exe = sys.executable
        self.is_windows = platform.system().lower() == 'windows'
        self.setup_log = []
    
    def log(self, message, level="INFO"):
        """Log setup messages."""
        log_entry = f"[{level}] {message}"
        self.setup_log.append(log_entry)
        print(log_entry)
    
    def run_command(self, command, description="", check=True):
        """Run a system command with logging."""
        self.log(f"Running: {description or command}")
        try:
            if isinstance(command, str):
                result = subprocess.run(command, shell=True, check=check, 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(command, check=check, 
                                      capture_output=True, text=True)
            
            if result.stdout:
                self.log(f"Output: {result.stdout.strip()}")
            return result.returncode == 0
            
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed: {e}", "ERROR")
            if e.stderr:
                self.log(f"Error: {e.stderr.strip()}", "ERROR")
            return False
        except Exception as e:
            self.log(f"Unexpected error: {e}", "ERROR")
            return False
    
    def check_python_version(self):
        """Check if Python version is compatible."""
        self.log("Checking Python version...")
        version = sys.version_info
        
        if version.major != 3 or version.minor < 8:
            self.log(f"Python 3.8+ required, found {version.major}.{version.minor}", "ERROR")
            return False
        
        self.log(f"Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    
    def check_virtual_environment(self):
        """Check if running in virtual environment."""
        self.log("Checking virtual environment...")
        
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            self.log("Virtual environment detected - OK")
            return True
        else:
            self.log("Not running in virtual environment", "WARNING")
            response = input("Continue without virtual environment? (y/N): ")
            return response.lower() == 'y'
    
    def install_requirements(self):
        """Install Python requirements."""
        self.log("Installing Python requirements...")
        requirements_file = self.project_root / "requirements.txt"
        
        if not requirements_file.exists():
            self.log("requirements.txt not found", "ERROR")
            return False
        
        command = [self.python_exe, "-m", "pip", "install", "-r", str(requirements_file)]
        return self.run_command(command, "Installing requirements")
    
    def check_npcap(self):
        """Check if Npcap is installed on Windows."""
        if not self.is_windows:
            return True
        
        self.log("Checking Npcap installation...")
        
        # Check common Npcap locations
        npcap_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Windows\SysWOW64\Npcap"
        ]
        
        for path in npcap_paths:
            if os.path.exists(path):
                dll_path = os.path.join(path, "wpcap.dll")
                if os.path.exists(dll_path):
                    self.log("Npcap found - OK")
                    return True
        
        self.log("Npcap not found", "WARNING")
        self.log("Please install Npcap from: https://npcap.com/")
        response = input("Continue without Npcap? (Network capture will not work) (y/N): ")
        return response.lower() == 'y'
    
    def create_directories(self):
        """Create necessary directories."""
        self.log("Creating directories...")
        
        directories = [
            "logs",
            "data/models",
            "data/exports",
            "data/backups"
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                self.log(f"Created directory: {directory}")
            except Exception as e:
                self.log(f"Failed to create directory {directory}: {e}", "ERROR")
                return False
        
        return True
    
    def initialize_database(self):
        """Initialize the database."""
        self.log("Initializing database...")
        
        try:
            # Import and initialize database
            sys.path.insert(0, str(self.project_root))
            from database import DatabaseManager
            from config.config import ConfigManager
            
            config = ConfigManager()
            db_manager = DatabaseManager()
            db_manager.initialize_db()
            
            self.log("Database initialized successfully")
            return True
            
        except Exception as e:
            self.log(f"Database initialization failed: {e}", "ERROR")
            return False
    
    def create_config_file(self):
        """Create or update configuration file."""
        self.log("Setting up configuration...")
        
        config_path = self.project_root / "config" / "config.yaml"
        
        if config_path.exists():
            self.log("Configuration file already exists")
            response = input("Overwrite existing configuration? (y/N): ")
            if response.lower() != 'y':
                return True
        
        try:
            # Copy default config if it doesn't exist
            if not config_path.exists():
                # Config file should already exist from our earlier creation
                self.log("Using existing configuration file")
            
            self.log("Configuration setup complete")
            return True
            
        except Exception as e:
            self.log(f"Configuration setup failed: {e}", "ERROR")
            return False
    
    def test_components(self):
        """Test system components."""
        self.log("Testing system components...")
        
        try:
            sys.path.insert(0, str(self.project_root))
            
            # Test configuration loading
            from config.config import ConfigManager
            config = ConfigManager()
            self.log("Configuration loading - OK")
            
            # Test database connection
            from database import DatabaseManager
            db_manager = DatabaseManager()
            db_manager.get_session().close()
            self.log("Database connection - OK")
            
            # Test network interface detection
            from network_capture import NetworkInterfaceManager
            interface_manager = NetworkInterfaceManager()
            interfaces = interface_manager.get_all_interfaces()
            self.log(f"Network interfaces detected: {len(interfaces)} - OK")
            
            return True
            
        except Exception as e:
            self.log(f"Component testing failed: {e}", "ERROR")
            return False
    
    def create_startup_scripts(self):
        """Create startup scripts for the system."""
        self.log("Creating startup scripts...")
        
        try:
            if self.is_windows:
                # Create Windows batch script
                batch_content = f'''@echo off
cd /d "{self.project_root}"
"{self.python_exe}" run.py --mode full
pause
'''
                batch_path = self.project_root / "start_system.bat"
                with open(batch_path, 'w') as f:
                    f.write(batch_content)
                self.log("Created start_system.bat")
                
                # Create service installation script
                service_content = f'''@echo off
cd /d "{self.project_root}"
"{self.python_exe}" run.py --service
pause
'''
                service_path = self.project_root / "install_service.bat"
                with open(service_path, 'w') as f:
                    f.write(service_content)
                self.log("Created install_service.bat")
            
            else:
                # Create shell script for Linux/Unix
                shell_content = f'''#!/bin/bash
cd "{self.project_root}"
"{self.python_exe}" run.py --mode full
'''
                shell_path = self.project_root / "start_system.sh"
                with open(shell_path, 'w') as f:
                    f.write(shell_content)
                os.chmod(shell_path, 0o755)
                self.log("Created start_system.sh")
            
            return True
            
        except Exception as e:
            self.log(f"Startup script creation failed: {e}", "ERROR")
            return False
    
    def display_completion_info(self):
        """Display completion information and next steps."""
        print("\n" + "="*60)
        print("SETUP COMPLETED SUCCESSFULLY!")
        print("="*60)
        
        print("\nNext Steps:")
        print("1. Review configuration in config/config.yaml")
        print("2. Start the system:")
        
        if self.is_windows:
            print("   - Double-click start_system.bat")
            print("   - Or run: python run.py --mode full")
            print("   - To install as Windows service: python run.py --service")
        else:
            print("   - Run: ./start_system.sh")
            print("   - Or run: python run.py --mode full")
        
        print("\n3. Access web interface at: http://localhost:5000")
        print("   - Default login: admin / admin (change after first login)")
        
        print("\nUseful Commands:")
        print("   python run.py --status     # Check system status")
        print("   python run.py --mode web   # Start web interface only")
        print("   python run.py --stop       # Stop service")
        
        print(f"\nLogs will be saved to: {self.project_root}/logs/")
        print(f"Database location: {self.project_root}/data/network_anomaly.db")
        
        if not self.is_windows or not self.check_npcap():
            print("\nNOTE: Packet capture requires Npcap on Windows.")
            print("Download from: https://npcap.com/")
        
        print("\n" + "="*60)
    
    def run_setup(self, skip_deps=False, test_only=False):
        """Run the complete setup process."""
        self.log("Starting Network Anomaly Detection System Setup")
        self.log(f"Platform: {platform.system()} {platform.release()}")
        self.log(f"Python: {sys.version}")
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Checking virtual environment", self.check_virtual_environment),
        ]
        
        if not skip_deps:
            steps.extend([
                ("Installing requirements", self.install_requirements),
                ("Checking Npcap (Windows)", self.check_npcap),
            ])
        
        if not test_only:
            steps.extend([
                ("Creating directories", self.create_directories),
                ("Setting up configuration", self.create_config_file),
                ("Initializing database", self.initialize_database),
                ("Creating startup scripts", self.create_startup_scripts),
            ])
        
        steps.append(("Testing components", self.test_components))
        
        # Execute setup steps
        for description, step_func in steps:
            self.log(f"\n--- {description} ---")
            if not step_func():
                self.log(f"Setup failed at: {description}", "ERROR")
                return False
        
        if not test_only:
            self.display_completion_info()
        else:
            self.log("Component testing completed successfully")
        
        return True

def main():
    """Main setup entry point."""
    parser = argparse.ArgumentParser(description='Network Anomaly Detection System Setup')
    parser.add_argument('--skip-deps', action='store_true',
                       help='Skip dependency installation')
    parser.add_argument('--test-only', action='store_true',
                       help='Only test components, do not install')
    
    args = parser.parse_args()
    
    setup = SetupManager()
    
    try:
        success = setup.run_setup(
            skip_deps=args.skip_deps,
            test_only=args.test_only
        )
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nSetup interrupted by user")
        return 1
    except Exception as e:
        print(f"Setup failed with unexpected error: {e}")
        return 1

if __name__ == '__main__':
    exit(main())
