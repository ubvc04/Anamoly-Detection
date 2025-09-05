#!/usr/bin/env python3
"""
Simple test script to verify core functionality
"""

def test_imports():
    """Test all critical imports"""
    try:
        print("Testing Flask...")
        import flask
        print("✓ Flask OK")
        
        print("Testing SQLAlchemy...")
        import sqlalchemy
        print("✓ SQLAlchemy OK")
        
        print("Testing Scapy...")
        import scapy
        print("✓ Scapy OK")
        
        print("Testing config...")
        from config.config import config
        print("✓ Config OK")
        
        print("Testing database module...")
        import database
        print("✓ Database module OK")
        
        print("Testing detector module...")
        import detector
        print("✓ Detector module OK")
        
        print("Testing network_capture module...")
        import network_capture
        print("✓ Network capture module OK")
        
        print("\n✅ All core modules can be imported successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Import error: {e}")
        return False

if __name__ == "__main__":
    test_imports()
