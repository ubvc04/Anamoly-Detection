#!/usr/bin/env python3
"""
Simple Flask App for Live Packet Display
Real-time network packet monitoring dashboard
"""

import os
import sys
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from live_packet_capture import get_live_capture

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'live-packet-capture-key'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global capture instance
capture = get_live_capture()

@app.route('/')
def index():
    """Main dashboard."""
    return render_template('live_dashboard.html')

@app.route('/api/packets')
def api_packets():
    """Get recent packets."""
    try:
        count = request.args.get('count', 50, type=int)
        packets = capture.get_recent_packets(count)
        return jsonify({
            'success': True,
            'packets': packets,
            'count': len(packets)
        })
    except Exception as e:
        logger.error(f"Error getting packets: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'packets': []
        })

@app.route('/api/statistics')
def api_statistics():
    """Get capture statistics."""
    try:
        stats = capture.get_statistics()
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'statistics': {}
        })

@app.route('/api/interfaces')
def api_interfaces():
    """Get available network interfaces."""
    try:
        interfaces = capture.get_available_interfaces()
        return jsonify({
            'success': True,
            'interfaces': interfaces
        })
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'interfaces': []
        })

@app.route('/api/capture/start', methods=['POST'])
def api_start_capture():
    """Start packet capture."""
    try:
        data = request.get_json() or {}
        interface = data.get('interface')
        
        success = capture.start_capture(interface)
        
        return jsonify({
            'success': success,
            'message': 'Capture started successfully' if success else 'Failed to start capture',
            'capturing': capture.is_capturing
        })
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'capturing': False
        })

@app.route('/api/capture/stop', methods=['POST'])
def api_stop_capture():
    """Stop packet capture."""
    try:
        capture.stop_capture()
        return jsonify({
            'success': True,
            'message': 'Capture stopped',
            'capturing': capture.is_capturing
        })
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'capturing': capture.is_capturing
        })

@app.route('/api/capture/status')
def api_capture_status():
    """Get capture status."""
    return jsonify({
        'success': True,
        'capturing': capture.is_capturing,
        'stats': capture.get_statistics()
    })

if __name__ == '__main__':
    print("Starting Live Packet Capture Dashboard...")
    print("Access the dashboard at: http://127.0.0.1:5001")
    
    # Auto-start capture
    try:
        interfaces = capture.get_available_interfaces()
        if interfaces:
            print(f"Available interfaces: {', '.join(interfaces)}")
            capture.start_capture()
            print("Packet capture started automatically")
        else:
            print("No network interfaces found")
    except Exception as e:
        print(f"Error auto-starting capture: {e}")
    
    app.run(host='0.0.0.0', port=5001, debug=False)
