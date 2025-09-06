#!/usr/bin/env python3
"""
Network Anomaly Detection System - Startup Script
Simplified launcher for the application with environment checks
"""

import sys
import os
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        print("❌ Error: Python 3.11 or higher is required")
        print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"✅ Python version: {version.major}.{version.minor}.{version.micro}")
    return True

def check_virtual_environment():
    """Check if virtual environment exists and is activated"""
    venv_path = Path("venv")
    if not venv_path.exists():
        print("❌ Virtual environment not found")
        print("   Run: python -m venv venv")
        return False
    
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment is activated")
        return True
    else:
        print("⚠️  Virtual environment exists but is not activated")
        if platform.system() == "Windows":
            print("   Run: venv\\Scripts\\activate")
        else:
            print("   Run: source venv/bin/activate")
        return False

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'flask', 'scapy', 'pandas', 'numpy', 'scikit-learn', 
        'plotly', 'psutil', 'sqlalchemy'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("   Run: pip install -r requirements.txt")
        return False
    
    print("✅ All required packages are installed")
    return True

def check_admin_privileges():
    """Check if running with admin privileges (required for packet capture)"""
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("⚠️  Warning: Administrator privileges required for packet capture")
                print("   Please run as Administrator for full functionality")
            else:
                print("✅ Running with Administrator privileges")
            return is_admin
        except:
            print("⚠️  Could not check admin privileges")
            return False
    else:
        # Unix-like systems
        if os.geteuid() != 0:
            print("⚠️  Warning: Root privileges may be required for packet capture")
            print("   Run with sudo if packet capture fails")
            return False
        print("✅ Running with root privileges")
        return True

def check_config():
    """Check if configuration file exists"""
    config_path = Path("config/config.yaml")
    if not config_path.exists():
        example_path = Path("config/config.yaml.example")
        if example_path.exists():
            print("⚠️  Configuration file not found")
            print("   Copy config/config.yaml.example to config/config.yaml")
            print("   Or the system will use default settings")
        else:
            print("⚠️  No configuration files found, using defaults")
        return False
    
    print("✅ Configuration file found")
    return True

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = ["data", "logs", "models"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Directories created/verified")

def main():
    """Main startup function"""
    print("🛡️  Network Anomaly Detection System - Startup Check")
    print("=" * 60)
    
    # Run all checks
    checks_passed = True
    
    if not check_python_version():
        checks_passed = False
    
    if not check_virtual_environment():
        checks_passed = False
    
    if not check_dependencies():
        checks_passed = False
    
    check_admin_privileges()  # Warning only, don't fail
    check_config()  # Warning only, don't fail
    
    create_directories()
    
    print("=" * 60)
    
    if not checks_passed:
        print("❌ Some checks failed. Please resolve the issues above.")
        return 1
    
    print("✅ All checks passed! Starting the application...")
    print("\n📊 Dashboard will be available at: http://localhost:5000")
    print("🔍 Monitor the console for real-time status updates")
    print("🛑 Press Ctrl+C to stop the application")
    print("-" * 60)
    
    # Start the application
    try:
        import app
        app.app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
        return 0
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
