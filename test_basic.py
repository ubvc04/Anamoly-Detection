#!/usr/bin/env python3
"""
Test script to verify Flask app can run without pandas/numpy dependencies
"""

def test_flask_basic():
    """Test basic Flask functionality"""
    try:
        print("Testing basic Flask setup...")
        
        from flask import Flask
        test_app = Flask(__name__)
        
        @test_app.route('/')
        def hello():
            return "Hello World!"
            
        print("✓ Flask app creation successful")
        
        # Test if we can import our config
        from config.config import config
        print("✓ Config import successful")
        
        print("\n✅ Basic Flask setup works!")
        return True
        
    except Exception as e:
        print(f"\n❌ Flask setup error: {e}")
        return False

def test_environment():
    """Test the Python environment"""
    import sys
    import os
    
    print("Python version:", sys.version)
    print("Working directory:", os.getcwd())
    print("Python path (first 3):", sys.path[:3])
    
    # Test virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✓ Virtual environment is active")
        return True
    else:
        print("❌ Virtual environment may not be active")
        return False

if __name__ == "__main__":
    print("=== Environment Test ===")
    test_environment()
    print("\n=== Flask Basic Test ===")
    test_flask_basic()
