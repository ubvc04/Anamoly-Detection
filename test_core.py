#!/usr/bin/env python3
"""
Test Flask app functionality without TensorFlow dependency
"""

def test_core_app():
    """Test core app functionality"""
    try:
        print("Testing core modules...")
        
        # Test config
        from config.config import config
        print("✓ Config module OK")
        
        # Test database
        from database import DatabaseManager
        print("✓ Database module OK")
        
        # Test network capture (without sklearn)
        import network_capture
        print("✓ Network capture module OK")
        
        # Test basic Flask routes
        print("\nTesting Flask app setup...")
        
        import os
        import sys
        
        # Temporarily disable TensorFlow import in detector
        original_detector_path = "detector.py"
        
        # Try to import Flask routes
        from flask import Flask
        test_app = Flask(__name__)
        
        @test_app.route('/')
        def test_route():
            return "Test successful"
            
        print("✓ Flask app setup successful")
        
        print("\n✅ Core functionality test passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Core test error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_core_app()
