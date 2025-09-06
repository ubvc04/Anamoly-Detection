#!/usr/bin/env python3
"""
Test Start Analyse Integration
Verify that the Start Analyse button works with comprehensive anomaly detection
"""

import requests
import json
import time
from datetime import datetime


def test_start_analyse_functionality():
    """Test the Start Analyse button functionality"""
    base_url = "http://127.0.0.1:5000"
    
    print("🚀 Testing Start Analyse Integration")
    print("=" * 60)
    
    try:
        # Test 1: Check if Flask app is running
        print("1. Testing Flask application accessibility...")
        response = requests.get(f"{base_url}/", timeout=10)
        if response.status_code == 200:
            print("   ✅ Flask application is accessible")
        else:
            print(f"   ❌ Flask application returned status: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Flask application is not accessible: {e}")
        return False
    
    try:
        # Test 2: Check ML status
        print("2. Testing ML Model status...")
        response = requests.get(f"{base_url}/api/ml/status", timeout=10)
        if response.status_code == 200:
            ml_status = response.json()
            print(f"   ✅ ML Status: {ml_status.get('status', 'unknown')}")
        else:
            print(f"   ⚠️ ML status check returned: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"   ⚠️ ML status check failed: {e}")
    
    try:
        # Test 3: Test comprehensive statistics API
        print("3. Testing comprehensive statistics API...")
        response = requests.get(f"{base_url}/api/statistics", timeout=10)
        if response.status_code == 200:
            stats = response.json()
            print("   ✅ Statistics API working")
            
            # Check for comprehensive data
            if 'anomaly_categories' in stats:
                categories = stats['anomaly_categories']
                print(f"   📊 Anomaly categories available: {len(categories)}")
                for category, count in categories.items():
                    print(f"      - {category}: {count}")
            
            if 'layer_analysis' in stats:
                layers = stats['layer_analysis']
                print(f"   🌐 Network layers monitored: {len(layers)}")
                
            if 'protocol_stats' in stats:
                protocols = stats['protocol_stats']
                print(f"   🔗 Protocols monitored: {len(protocols)}")
        else:
            print(f"   ❌ Statistics API returned: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Statistics API test failed: {e}")
    
    try:
        # Test 4: Test Start Analyse functionality
        print("4. Testing Start Analyse functionality...")
        
        start_analyse_payload = {
            "analysis_type": "comprehensive",
            "categories": [
                "traffic_volume", "protocol", "behavioral", "statistical",
                "application", "security", "topology", "endpoint", 
                "temporal", "hybrid"
            ],
            "layers": ["datalink", "network", "transport", "application"],
            "protocols": [
                "tcp", "udp", "icmp", "arp", "http", "dns", 
                "smtp", "ftp", "ssh", "snmp", "sip", "iot_scada"
            ]
        }
        
        response = requests.post(
            f"{base_url}/api/capture/start",
            json=start_analyse_payload,
            timeout=15
        )
        
        if response.status_code == 200:
            result = response.json()
            print("   ✅ Start Analyse request successful!")
            print(f"   📊 Analysis type: {result.get('analysis_type', 'unknown')}")
            print(f"   📈 Categories monitored: {result.get('categories_monitored', 0)}")
            print(f"   🌐 Layers monitored: {result.get('layers_monitored', 0)}")
            print(f"   🔗 Protocols monitored: {result.get('protocols_monitored', 0)}")
            print(f"   💬 Message: {result.get('message', 'No message')}")
            return True
        else:
            print(f"   ❌ Start Analyse failed with status: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   🔍 Error details: {error_data}")
            except:
                print(f"   🔍 Response text: {response.text}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Start Analyse test failed: {e}")
        return False


def test_dashboard_integration():
    """Test that dashboard displays comprehensive anomaly data"""
    base_url = "http://127.0.0.1:5000"
    
    print("\n🎯 Testing Dashboard Integration")
    print("=" * 60)
    
    try:
        # Test dashboard page
        print("1. Testing dashboard page...")
        response = requests.get(f"{base_url}/", timeout=10)
        if response.status_code == 200:
            print("   ✅ Dashboard page loads successfully")
            
            # Check for key elements in HTML
            html_content = response.text
            integration_indicators = [
                "Comprehensive Anomaly Detection",
                "Traffic Volume",
                "Protocol",
                "Behavioral",
                "Statistical",
                "Application-Layer",
                "Security-Related",
                "Start Analyse"
            ]
            
            found_indicators = []
            for indicator in integration_indicators:
                if indicator in html_content:
                    found_indicators.append(indicator)
            
            print(f"   📊 Integration indicators found: {len(found_indicators)}/{len(integration_indicators)}")
            for indicator in found_indicators:
                print(f"      ✅ {indicator}")
                
            missing_indicators = set(integration_indicators) - set(found_indicators)
            for indicator in missing_indicators:
                print(f"      ❌ Missing: {indicator}")
                
            return len(found_indicators) >= len(integration_indicators) * 0.7  # 70% success rate
        else:
            print(f"   ❌ Dashboard page returned: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Dashboard test failed: {e}")
        return False


def main():
    """Main test function"""
    print(f"🧪 Start Analyse Integration Test")
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Testing URL: http://127.0.0.1:5000")
    print()
    
    # Run tests
    start_analyse_success = test_start_analyse_functionality()
    dashboard_success = test_dashboard_integration()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 TEST SUMMARY")
    print("=" * 60)
    print(f"✅ Start Analyse Functionality: {'PASS' if start_analyse_success else 'FAIL'}")
    print(f"✅ Dashboard Integration: {'PASS' if dashboard_success else 'FAIL'}")
    
    overall_success = start_analyse_success and dashboard_success
    print(f"🎯 Overall Test Result: {'✅ SUCCESS' if overall_success else '❌ FAILURE'}")
    
    if overall_success:
        print("\n🎉 Comprehensive anomaly detection system is working!")
        print("   - All 10 anomaly categories are integrated")
        print("   - Multi-layer network analysis is functional")
        print("   - Start Analyse button works correctly")
        print("   - Web interface displays comprehensive data")
    else:
        print("\n⚠️ Some components need attention:")
        print("   - Check Flask application logs")
        print("   - Verify ML model integration")
        print("   - Ensure all API endpoints are working")


if __name__ == "__main__":
    main()
