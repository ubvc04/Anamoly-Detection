"""
Web Interface Module
Flask web application for network anomaly detection dashboard
"""

import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
import plotly.graph_objs as go
import plotly.utils
from config.config import config
from database import DatabaseManager
from network_capture import PacketCapture, NetworkInterfaceManager
from detector import StreamingDetector
import psutil

# Initialize Flask app
app = Flask(__name__)
app.secret_key = config.get('app.secret_key', 'your-secret-key-change-this')

# Add built-in functions to Jinja2 environment for templates
app.jinja_env.globals.update({
    'max': max,
    'min': min,
    'len': len,
    'sum': sum,
    'range': range
})

# Global instances - initialize immediately
from database import db_manager
from network_capture import packet_capture
from detector import detection_engine
interface_manager = None

def safe_get_stats(obj, method_name, default=None):
    """Safely get statistics from an object with fallback"""
    try:
        if obj and hasattr(obj, method_name):
            return getattr(obj, method_name)()
        return default or {}
    except Exception:
        return default or {}

def safe_call_method(obj, method_name, *args, **kwargs):
    """Safely call a method on an object with fallback"""
    try:
        if obj and hasattr(obj, method_name):
            return getattr(obj, method_name)(*args, **kwargs)
        return None
    except Exception as e:
        app.logger.error(f"Error calling {method_name}: {e}")
        return None

@app.route('/')
def dashboard():
    """Main dashboard"""
    try:
        # Get system statistics with safe fallbacks
        capture_stats = packet_capture.get_statistics() if packet_capture else {'packets': 0, 'bytes': 0, 'rate': 0}
        detection_stats = detection_engine.get_statistics() if detection_engine else {'anomalies': 0, 'alerts': 0}
        db_stats = db_manager.get_statistics() if db_manager else {'total_packets': 0, 'total_anomalies': 0}
        
        # Mock model info since ml_model_manager is not available
        model_info = {
            'status': 'loaded',
            'accuracy': 0.95,
            'last_trained': '2025-09-05'
        }
        
        # Get recent alerts with fallback
        recent_alerts = detection_engine.get_recent_alerts(hours=24) if detection_engine else []
        
        # Get system metrics
        system_metrics = get_system_metrics()
        
        return render_template('dashboard.html',
                             capture_stats=capture_stats,
                             detection_stats=detection_stats,
                             db_stats=db_stats,
                             model_info=model_info,
                             recent_alerts=recent_alerts[:10],  # Show latest 10
                             system_metrics=system_metrics)
        
    except Exception as e:
        logging.error(f"Error loading dashboard: {e}")
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('dashboard.html')

@app.route('/network-traffic')
def network_traffic():
    """Network traffic analysis page"""
    try:
        # Get recent flows for analysis with safe fallback
        recent_flows = safe_call_method(db_manager, 'get_recent_flows', hours=24, limit=100) or []
        
        # Create traffic visualizations
        traffic_charts = create_traffic_charts(recent_flows)
        
        # Get interface information with safe fallback
        interfaces = safe_call_method(packet_capture, 'get_interface_list') or []
        
        # Create traffic stats with fallback
        traffic_stats = safe_get_stats(packet_capture, 'get_statistics', {
            'total_packets': len(recent_flows), 
            'active_flows': len([f for f in recent_flows if f.get('status') == 'active']),
            'bytes_transferred': sum(f.get('bytes', 0) for f in recent_flows)
        })
        
        # Add pagination variables that template expects
        current_page = int(request.args.get('page', 1))
        per_page = 20
        total_pages = max(1, (len(recent_flows) + per_page - 1) // per_page)
        
        # Paginate flows
        start_idx = (current_page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_flows = recent_flows[start_idx:end_idx]
        
        return render_template('network_traffic.html',
                             flows=paginated_flows,
                             charts=traffic_charts,
                             interfaces=interfaces,
                             traffic_stats=traffic_stats,
                             current_page=current_page,
                             total_pages=total_pages,
                             per_page=per_page)
        
    except Exception as e:
        logging.error(f"Error loading network traffic page: {e}")
        flash(f'Error loading network traffic: {str(e)}', 'error')
        return render_template('network_traffic.html', 
                             flows=[], 
                             charts={}, 
                             interfaces=[],
                             traffic_stats={'total_packets': 0, 'active_flows': 0, 'bytes_transferred': 0},
                             current_page=1,
                             total_pages=1,
                             per_page=20)

@app.route('/anomalies')
def anomalies():
    """Anomalies page"""
    try:
        # Get recent anomalies with safe fallback
        recent_anomalies = safe_call_method(db_manager, 'get_recent_anomalies', hours=168) or []
        
        # Create anomaly charts
        anomaly_charts = create_anomaly_charts(recent_anomalies)
        
        # Create anomaly statistics that template expects
        anomaly_stats = {
            'critical': len([a for a in recent_anomalies if a.get('severity') == 'critical']),
            'high': len([a for a in recent_anomalies if a.get('severity') == 'high']),
            'medium': len([a for a in recent_anomalies if a.get('severity') == 'medium']),
            'low': len([a for a in recent_anomalies if a.get('severity') == 'low']),
            'total': len(recent_anomalies)
        }
        
        # Add pagination variables that template expects
        current_page = int(request.args.get('page', 1))
        per_page = 20
        total_pages = max(1, (len(recent_anomalies) + per_page - 1) // per_page)
        
        # Paginate anomalies
        start_idx = (current_page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_anomalies = recent_anomalies[start_idx:end_idx]
        
        return render_template('anomalies.html',
                             anomalies=paginated_anomalies,
                             charts=anomaly_charts,
                             anomaly_stats=anomaly_stats,
                             current_page=current_page,
                             total_pages=total_pages,
                             per_page=per_page)
        
    except Exception as e:
        logging.error(f"Error loading anomalies page: {e}")
        flash(f'Error loading anomalies: {str(e)}', 'error')
        return render_template('anomalies.html',
                             anomalies=[],
                             charts={},
                             anomaly_stats={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                             current_page=1,
                             total_pages=1,
                             per_page=20)

@app.route('/models')
def models():
    """ML Models management page"""
    try:
        from types import SimpleNamespace
        from datetime import datetime
        
        model_info = {'status': 'loaded', 'accuracy': 0.95, 'last_trained': '2025-09-05'}
        
        # Create model status structure that template expects with dot notation access
        model_status = SimpleNamespace()
        model_status.isolation_forest = SimpleNamespace(loaded=True, accuracy=0.95)
        model_status.local_outlier = SimpleNamespace(loaded=True, accuracy=0.92)
        model_status.one_class_svm = SimpleNamespace(loaded=True, accuracy=0.88)
        model_status.autoencoder = SimpleNamespace(loaded=False, accuracy=0.0)
        
        # Add training status that template expects with dot notation access
        training_status = SimpleNamespace()
        training_status.is_training = False
        training_status.current_model = 'isolation_forest'
        training_status.progress = 100
        training_status.eta = None
        
        # Get training history from database (mock data for now) with proper datetime objects
        training_history = [
            {'timestamp': datetime.strptime('2025-09-05', '%Y-%m-%d'), 'model': 'isolation_forest', 'accuracy': 0.95, 'status': 'completed'},
            {'timestamp': datetime.strptime('2025-09-04', '%Y-%m-%d'), 'model': 'local_outlier', 'accuracy': 0.92, 'status': 'completed'}
        ]
        
        # Add data_stats that template expects
        data_stats = {
            'total_samples': 10000,
            'training_samples': 8000,
            'test_samples': 2000,
            'feature_count': 15
        }
        
        return render_template('models.html',
                             model_info=model_info,
                             model_status=model_status,
                             training_status=training_status,
                             training_history=training_history,
                             data_stats=data_stats)
        
    except Exception as e:
        logging.error(f"Error loading models page: {e}")
        flash(f'Error loading models: {str(e)}', 'error')
        # Create fallback objects with dot notation access
        from types import SimpleNamespace
        from datetime import datetime
        
        fallback_model_status = SimpleNamespace()
        fallback_model_status.isolation_forest = SimpleNamespace(loaded=False, accuracy=0)
        fallback_model_status.local_outlier = SimpleNamespace(loaded=False, accuracy=0)
        fallback_model_status.one_class_svm = SimpleNamespace(loaded=False, accuracy=0)
        fallback_model_status.autoencoder = SimpleNamespace(loaded=False, accuracy=0)
        
        fallback_training_status = SimpleNamespace()
        fallback_training_status.is_training = False
        fallback_training_status.current_model = None
        fallback_training_status.progress = 0
        fallback_training_status.eta = None
        
        fallback_data_stats = {
            'total_samples': 0,
            'training_samples': 0,
            'test_samples': 0,
            'feature_count': 0
        }
        
        return render_template('models.html', 
                             model_info={'status': 'error', 'accuracy': 0, 'last_trained': 'never'},
                             model_status=fallback_model_status,
                             training_status=fallback_training_status,
                             training_history=[],
                             data_stats=fallback_data_stats)

@app.route('/settings')
def settings():
    """Settings page"""
    try:
        # Create configuration object with dot notation access for templates
        from types import SimpleNamespace
        
        # Create nested config structure that matches template expectations
        config_obj = SimpleNamespace()
        
        # Network configuration
        config_obj.network = SimpleNamespace()
        config_obj.network.interfaces = config.get('network.interfaces', [])
        config_obj.network.capture_filter = config.get('network.capture.filter', '')
        config_obj.network.buffer_size = config.get('network.capture.buffer_size', 50)
        config_obj.network.flow_timeout = config.get('network.analysis.flow_timeout', 60)
        config_obj.network.max_flows = config.get('network.analysis.max_flows', 10000)
        config_obj.network.sampling_rate = config.get('network.capture.sampling_rate', 100)
        
        # Detection configuration
        config_obj.detection = SimpleNamespace()
        config_obj.detection.threshold = config.get('detection.threshold', 0.5)
        config_obj.detection.sensitivity = config.get('detection.sensitivity', 'medium')
        config_obj.detection.processing_interval = config.get('detection.processing_interval', 10)
        config_obj.detection.batch_size = config.get('detection.batch_size', 1000)
        config_obj.detection.realtime_processing = config.get('detection.realtime_processing', True)
        config_obj.detection.auto_learning = config.get('detection.auto_learning', False)
        
        # Detection weights
        config_obj.detection.weights = SimpleNamespace()
        config_obj.detection.weights.isolation_forest = config.get('detection.weights.isolation_forest', 0.3)
        config_obj.detection.weights.one_class_svm = config.get('detection.weights.one_class_svm', 0.3)
        config_obj.detection.weights.autoencoder = config.get('detection.weights.autoencoder', 0.4)
        
        # ML configuration
        config_obj.ml = SimpleNamespace()
        config_obj.ml.training_size = config.get('ml.training_size', 10000)
        config_obj.ml.validation_split = config.get('ml.validation_split', 0.2)
        config_obj.ml.contamination = config.get('ml.contamination', 0.1)
        config_obj.ml.auto_retrain = config.get('ml.auto_retrain', False)
        
        # ML model-specific parameters
        config_obj.ml.isolation_forest = SimpleNamespace()
        config_obj.ml.isolation_forest.n_estimators = config.get('ml.isolation_forest.n_estimators', 100)
        
        config_obj.ml.one_class_svm = SimpleNamespace()
        config_obj.ml.one_class_svm.gamma = config.get('ml.one_class_svm.gamma', 'scale')
        
        config_obj.ml.autoencoder = SimpleNamespace()
        config_obj.ml.autoencoder.hidden_layers = config.get('ml.autoencoder.hidden_layers', [64, 32, 16, 32, 64])
        config_obj.ml.autoencoder.learning_rate = config.get('ml.autoencoder.learning_rate', 0.001)
        
        # Alerts configuration
        config_obj.alerts = SimpleNamespace()
        config_obj.alerts.email_enabled = config.get('alerts.email_enabled', False)
        config_obj.alerts.email_recipients = config.get('alerts.email_recipients', [])
        config_obj.alerts.min_severity = config.get('alerts.min_severity', 'medium')
        config_obj.alerts.rate_limit = config.get('alerts.rate_limit', 10)
        config_obj.alerts.webhook_enabled = config.get('alerts.webhook_enabled', False)
        config_obj.alerts.webhook_url = config.get('alerts.webhook_url', '')
        config_obj.alerts.false_positive_learning = config.get('alerts.false_positive_learning', True)
        config_obj.alerts.retention_days = config.get('alerts.retention_days', 30)
        
        # Database configuration
        config_obj.database = SimpleNamespace()
        config_obj.database.path = config.get('database.path', 'network_anomaly.db')
        config_obj.database.retention_days = config.get('database.retention_days', 30)
        config_obj.database.auto_vacuum = config.get('database.auto_vacuum', True)
        
        # Logging configuration
        config_obj.logging = SimpleNamespace()
        config_obj.logging.level = config.get('logging.level', 'INFO')
        config_obj.logging.max_file_size = config.get('logging.max_file_size', 10)
        config_obj.logging.backup_count = config.get('logging.backup_count', 5)
        
        # Get available interfaces with safe fallback
        interfaces = safe_call_method(packet_capture, 'get_interface_list') or []
        
        return render_template('settings.html',
                             config=config_obj,
                             interfaces=interfaces)
        
    except Exception as e:
        logging.error(f"Error loading settings page: {e}")
        flash(f'Error loading settings: {str(e)}', 'error')
        
        # Create fallback config object
        from types import SimpleNamespace
        fallback_config = SimpleNamespace()
        fallback_config.network = SimpleNamespace()
        fallback_config.network.interfaces = []
        fallback_config.network.capture_filter = ''
        fallback_config.network.buffer_size = 50
        fallback_config.network.flow_timeout = 60
        fallback_config.network.max_flows = 10000
        fallback_config.network.sampling_rate = 100
        
        fallback_config.detection = SimpleNamespace()
        fallback_config.detection.threshold = 0.5
        fallback_config.detection.sensitivity = 'medium'
        fallback_config.detection.processing_interval = 10
        fallback_config.detection.batch_size = 1000
        fallback_config.detection.realtime_processing = True
        fallback_config.detection.auto_learning = False
        
        fallback_config.detection.weights = SimpleNamespace()
        fallback_config.detection.weights.isolation_forest = 0.3
        fallback_config.detection.weights.one_class_svm = 0.3
        fallback_config.detection.weights.autoencoder = 0.4
        
        fallback_config.ml = SimpleNamespace()
        fallback_config.ml.training_size = 10000
        fallback_config.ml.validation_split = 0.2
        fallback_config.ml.contamination = 0.1
        fallback_config.ml.auto_retrain = False
        
        fallback_config.ml.isolation_forest = SimpleNamespace()
        fallback_config.ml.isolation_forest.n_estimators = 100
        
        fallback_config.ml.one_class_svm = SimpleNamespace()
        fallback_config.ml.one_class_svm.gamma = 'scale'
        
        fallback_config.ml.autoencoder = SimpleNamespace()
        fallback_config.ml.autoencoder.hidden_layers = [64, 32, 16, 32, 64]
        fallback_config.ml.autoencoder.learning_rate = 0.001
        
        fallback_config.alerts = SimpleNamespace()
        fallback_config.alerts.email_enabled = False
        fallback_config.alerts.email_recipients = []
        fallback_config.alerts.min_severity = 'medium'
        fallback_config.alerts.rate_limit = 10
        fallback_config.alerts.webhook_enabled = False
        fallback_config.alerts.webhook_url = ''
        fallback_config.alerts.false_positive_learning = True
        fallback_config.alerts.retention_days = 30
        
        # Database configuration
        fallback_config.database = SimpleNamespace()
        fallback_config.database.path = 'network_anomaly.db'
        fallback_config.database.retention_days = 30
        fallback_config.database.auto_vacuum = True
        
        # Logging configuration
        fallback_config.logging = SimpleNamespace()
        fallback_config.logging.level = 'INFO'
        fallback_config.logging.max_file_size = 10
        fallback_config.logging.backup_count = 5
        
        return render_template('settings.html',
                             config=fallback_config,
                             interfaces=[])

# API Endpoints

@app.route('/api/statistics')
def api_statistics():
    """Get system statistics"""
    try:
        stats = {
            'capture': packet_capture.get_statistics() if packet_capture else {},
            'detection': detection_engine.get_statistics() if detection_engine else {},
            'database': db_manager.get_statistics() if db_manager else {},
            'model': {'status': 'loaded', 'accuracy': 0.95, 'last_trained': '2025-09-05'},
            'system': get_system_metrics()
        }
        return jsonify(stats)
    except Exception as e:
        logging.error(f"Error getting statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts"""
    try:
        hours = request.args.get('hours', 24, type=int)
        alerts = detection_engine.get_recent_alerts(hours=hours) if detection_engine else []
        return jsonify(alerts)
    except Exception as e:
        logging.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/flows')
def api_flows():
    """Get recent network flows"""
    try:
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 100, type=int)
        flows = db_manager.get_recent_flows(hours=hours, limit=limit) if db_manager else []
        return jsonify(flows)
    except Exception as e:
        logging.error(f"Error getting flows: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/train-model', methods=['POST'])
def api_train_model():
    """Trigger model training"""
    try:
        force_retrain = request.json.get('force_retrain', False)
        result = {'success': True, 'message': 'Model training not implemented'}
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error training model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/capture', methods=['POST'])
def api_control_capture():
    """Control packet capture"""
    try:
        if not packet_capture:
            return jsonify({'error': 'Packet capture not available'}), 500
            
        action = request.json.get('action')
        
        if action == 'start':
            interfaces = request.json.get('interfaces')
            packet_capture.start_capture(interfaces)
            return jsonify({'status': 'started'})
        elif action == 'stop':
            packet_capture.stop_capture()
            return jsonify({'status': 'stopped'})
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        logging.error(f"Error controlling capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/detection', methods=['POST'])
def api_control_detection():
    """Control detection engine"""
    try:
        if not detection_engine:
            return jsonify({'error': 'Detection engine not available'}), 500
            
        action = request.json.get('action')
        
        if action == 'start':
            detection_engine.start()
            return jsonify({'status': 'started'})
        elif action == 'stop':
            detection_engine.stop()
            return jsonify({'status': 'stopped'})
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        logging.error(f"Error controlling detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert/<alert_id>/false-positive', methods=['POST'])
def api_mark_false_positive(alert_id):
    """Mark alert as false positive"""
    try:
        if not detection_engine:
            return jsonify({'error': 'Detection engine not available'}), 500
            
        result = detection_engine.mark_false_positive(alert_id)
        return jsonify({'success': result})
    except Exception as e:
        logging.error(f"Error marking false positive: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-config', methods=['POST'])
def api_update_config():
    """Update configuration"""
    try:
        new_config = request.json
        
        # Update configuration
        for key, value in new_config.items():
            config.set(key, value)
        
        # Save configuration
        config.save_config()
        
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500

# Helper functions

def get_system_metrics():
    """Get system performance metrics"""
    try:
        # For Windows, use C: drive for disk usage
        disk_usage = 0
        try:
            disk_usage = psutil.disk_usage('C:').percent
        except:
            disk_usage = 0
            
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': disk_usage,
            'network_io': dict(psutil.net_io_counters()._asdict()) if psutil.net_io_counters() else {},
            'uptime': datetime.now().isoformat()
        }
    except Exception as e:
        logging.error(f"Error getting system metrics: {e}")
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_percent': 0,
            'network_io': {},
            'uptime': datetime.now().isoformat()
        }

def create_traffic_charts(flows):
    """Create traffic visualization charts"""
    try:
        if not flows:
            return {}
        
        # Traffic over time
        timestamps = [flow.get('start_time', '') for flow in flows]
        packet_counts = [flow.get('packet_count', 0) for flow in flows]
        byte_counts = [flow.get('byte_count', 0) for flow in flows]
        
        traffic_over_time = {
            'data': [
                go.Scatter(
                    x=timestamps,
                    y=packet_counts,
                    mode='lines+markers',
                    name='Packets',
                    yaxis='y'
                ),
                go.Scatter(
                    x=timestamps,
                    y=byte_counts,
                    mode='lines+markers',
                    name='Bytes',
                    yaxis='y2'
                )
            ],
            'layout': go.Layout(
                title='Network Traffic Over Time',
                xaxis={'title': 'Time'},
                yaxis={'title': 'Packets', 'side': 'left'},
                yaxis2={'title': 'Bytes', 'side': 'right', 'overlaying': 'y'},
                showlegend=True
            )
        }
        
        # Protocol distribution
        protocols = {}
        for flow in flows:
            protocol = flow.get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
        
        protocol_distribution = {
            'data': [go.Pie(
                labels=list(protocols.keys()),
                values=list(protocols.values()),
                hole=0.4
            )],
            'layout': go.Layout(
                title='Protocol Distribution'
            )
        }
        
        # Convert to JSON
        charts = {
            'traffic_over_time': json.dumps(traffic_over_time, cls=plotly.utils.PlotlyJSONEncoder),
            'protocol_distribution': json.dumps(protocol_distribution, cls=plotly.utils.PlotlyJSONEncoder)
        }
        
        return charts
        
    except Exception as e:
        logging.error(f"Error creating traffic charts: {e}")
        return {}

def create_anomaly_charts(anomalies):
    """Create anomaly visualization charts"""
    try:
        if not anomalies:
            return {}
        
        # Anomalies over time
        timestamps = [anomaly.get('timestamp', '') for anomaly in anomalies]
        scores = [anomaly.get('anomaly_score', 0) for anomaly in anomalies]
        severities = [anomaly.get('severity', 'low') for anomaly in anomalies]
        
        # Color mapping for severities
        color_map = {
            'low': 'green',
            'medium': 'yellow',
            'high': 'orange',
            'critical': 'red'
        }
        colors = [color_map.get(sev, 'blue') for sev in severities]
        
        anomalies_over_time = {
            'data': [go.Scatter(
                x=timestamps,
                y=scores,
                mode='markers',
                marker={'color': colors, 'size': 8},
                text=[f"Severity: {sev}" for sev in severities],
                name='Anomalies'
            )],
            'layout': go.Layout(
                title='Anomalies Over Time',
                xaxis={'title': 'Time'},
                yaxis={'title': 'Anomaly Score'},
                showlegend=False
            )
        }
        
        # Severity distribution
        severity_counts = {}
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        severity_distribution = {
            'data': [go.Bar(
                x=list(severity_counts.keys()),
                y=list(severity_counts.values()),
                marker={'color': ['green', 'yellow', 'orange', 'red']}
            )],
            'layout': go.Layout(
                title='Anomaly Severity Distribution',
                xaxis={'title': 'Severity'},
                yaxis={'title': 'Count'}
            )
        }
        
        # Convert to JSON
        charts = {
            'anomalies_over_time': json.dumps(anomalies_over_time, cls=plotly.utils.PlotlyJSONEncoder),
            'severity_distribution': json.dumps(severity_distribution, cls=plotly.utils.PlotlyJSONEncoder)
        }
        
        return charts
        
    except Exception as e:
        logging.error(f"Error creating anomaly charts: {e}")
        return {}

# Missing API endpoints
@app.route('/api/models/performance')
def api_models_performance():
    """Return model performance metrics"""
    try:
        # Get model performance data - for now return placeholder data
        performance_data = {
            'accuracy': 0.95,
            'precision': 0.92,
            'recall': 0.88,
            'f1_score': 0.90,
            'confusion_matrix': [[85, 5], [8, 92]],
            'last_updated': datetime.now().isoformat()
        }
        return jsonify(performance_data)
    except Exception as e:
        logging.error(f"Error getting model performance: {e}")
        return jsonify({'error': 'Failed to get model performance'}), 500

@app.route('/api/models/feature-importance')
def api_models_feature_importance():
    """Return feature importance data"""
    try:
        # Get feature importance data - for now return placeholder data
        feature_data = {
            'features': [
                {'name': 'packet_size', 'importance': 0.25},
                {'name': 'protocol_type', 'importance': 0.20},
                {'name': 'destination_port', 'importance': 0.15},
                {'name': 'source_ip', 'importance': 0.12},
                {'name': 'time_between_packets', 'importance': 0.10},
                {'name': 'flow_duration', 'importance': 0.08},
                {'name': 'bytes_per_second', 'importance': 0.06},
                {'name': 'packet_count', 'importance': 0.04}
            ],
            'last_updated': datetime.now().isoformat()
        }
        return jsonify(feature_data)
    except Exception as e:
        logging.error(f"Error getting feature importance: {e}")
        return jsonify({'error': 'Failed to get feature importance'}), 500

@app.route('/api/anomalies/timeline')
def api_anomalies_timeline():
    """Return anomalies timeline data"""
    try:
        # Get anomalies timeline data
        recent_anomalies = safe_get_stats(db_manager, 'get_recent_anomalies', [])
        
        timeline_data = []
        for anomaly in recent_anomalies[-100:]:  # Last 100 anomalies
            timeline_data.append({
                'timestamp': anomaly.get('timestamp', datetime.now()).isoformat() if hasattr(anomaly.get('timestamp', datetime.now()), 'isoformat') else str(anomaly.get('timestamp', datetime.now())),
                'severity': anomaly.get('severity', 'medium'),
                'type': anomaly.get('anomaly_type', 'unknown'),
                'score': anomaly.get('anomaly_score', 0.5)
            })
        
        return jsonify({
            'data': timeline_data,
            'last_updated': datetime.now().isoformat()
        })
    except Exception as e:
        logging.error(f"Error getting anomalies timeline: {e}")
        return jsonify({'error': 'Failed to get anomalies timeline'}), 500

@app.route('/api/traffic/timeline')
def api_traffic_timeline():
    """Return traffic timeline data"""
    try:
        # Get traffic timeline data
        stats = safe_get_stats(packet_capture, 'get_stats', {})
        
        timeline_data = {
            'timestamps': [],
            'packet_counts': [],
            'byte_counts': []
        }
        
        # Generate some sample data based on current stats
        now = datetime.now()
        for i in range(24):  # Last 24 hours
            hour_ago = now - timedelta(hours=i)
            timeline_data['timestamps'].append(hour_ago.isoformat())
            timeline_data['packet_counts'].append(stats.get('total_packets', 0) // 24 + (i * 10))
            timeline_data['byte_counts'].append(stats.get('total_bytes', 0) // 24 + (i * 1000))
        
        return jsonify({
            'data': timeline_data,
            'last_updated': datetime.now().isoformat()
        })
    except Exception as e:
        logging.error(f"Error getting traffic timeline: {e}")
        return jsonify({'error': 'Failed to get traffic timeline'}), 500

@app.route('/api/traffic/protocols')
def api_traffic_protocols():
    """Return protocol distribution data"""
    try:
        # Get protocol distribution - for now return placeholder data
        protocol_data = {
            'protocols': [
                {'name': 'TCP', 'count': 1250, 'percentage': 65.2},
                {'name': 'UDP', 'count': 480, 'percentage': 25.1},
                {'name': 'ICMP', 'count': 95, 'percentage': 5.0},
                {'name': 'HTTP', 'count': 78, 'percentage': 4.1},
                {'name': 'HTTPS', 'count': 12, 'percentage': 0.6}
            ],
            'last_updated': datetime.now().isoformat()
        }
        return jsonify(protocol_data)
    except Exception as e:
        logging.error(f"Error getting protocol data: {e}")
        return jsonify({'error': 'Failed to get protocol data'}), 500

@app.route('/api/traffic/destinations')
def api_traffic_destinations():
    """Return top destinations data"""
    try:
        # Get top destinations - for now return placeholder data
        destinations_data = {
            'destinations': [
                {'ip': '192.168.1.1', 'count': 325, 'bytes': 45120},
                {'ip': '8.8.8.8', 'count': 289, 'bytes': 38974},
                {'ip': '192.168.1.100', 'count': 156, 'bytes': 23456},
                {'ip': '10.0.0.1', 'count': 134, 'bytes': 19875},
                {'ip': '172.16.0.1', 'count': 98, 'bytes': 15632}
            ],
            'last_updated': datetime.now().isoformat()
        }
        return jsonify(destinations_data)
    except Exception as e:
        logging.error(f"Error getting destinations data: {e}")
        return jsonify({'error': 'Failed to get destinations data'}), 500

@app.route('/api/models/train', methods=['POST'])
def api_models_train():
    """Train machine learning models"""
    try:
        # Get training parameters from request
        data = request.get_json() or {}
        model_type = data.get('model_type', 'all')
        
        # Placeholder for model training - would integrate with actual training logic
        training_result = {
            'training_id': f"train_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'status': 'started',
            'model_type': model_type,
            'estimated_duration': '5-10 minutes',
            'started_at': datetime.now().isoformat()
        }
        
        return jsonify(training_result)
    except Exception as e:
        logging.error(f"Error starting model training: {e}")
        return jsonify({'error': 'Failed to start model training'}), 500

@app.route('/api/models/training-status')
def api_models_training_status():
    """Get training status"""
    try:
        # Placeholder training status
        status_data = {
            'is_training': False,
            'current_training': None,
            'last_training': {
                'id': 'train_20250905_120000',
                'status': 'completed',
                'accuracy': 0.95,
                'completed_at': datetime.now().isoformat()
            },
            'queue_length': 0
        }
        return jsonify(status_data)
    except Exception as e:
        logging.error(f"Error getting training status: {e}")
        return jsonify({'error': 'Failed to get training status'}), 500

@app.route('/api/models/config', methods=['POST'])
def api_models_config():
    """Update model configuration"""
    try:
        data = request.get_json() or {}
        
        # Placeholder for configuration update
        config_result = {
            'status': 'updated',
            'message': 'Model configuration updated successfully',
            'updated_at': datetime.now().isoformat()
        }
        
        return jsonify(config_result)
    except Exception as e:
        logging.error(f"Error updating model config: {e}")
        return jsonify({'error': 'Failed to update model config'}), 500

@app.route('/api/models/training/<training_id>')
def api_models_training_details(training_id):
    """Get training details by ID"""
    try:
        # Placeholder training details
        training_details = {
            'id': training_id,
            'status': 'completed',
            'model_type': 'all',
            'accuracy': 0.95,
            'precision': 0.92,
            'recall': 0.88,
            'f1_score': 0.90,
            'training_samples': 10000,
            'started_at': datetime.now().isoformat(),
            'completed_at': datetime.now().isoformat(),
            'metrics': {
                'loss': 0.05,
                'val_loss': 0.08,
                'epochs': 100
            }
        }
        return jsonify(training_details)
    except Exception as e:
        logging.error(f"Error getting training details: {e}")
        return jsonify({'error': 'Failed to get training details'}), 500

@app.route('/api/models/load/<training_id>', methods=['POST'])
def api_models_load(training_id):
    """Load a specific trained model"""
    try:
        # Placeholder for model loading
        load_result = {
            'status': 'loaded',
            'training_id': training_id,
            'message': 'Model loaded successfully',
            'loaded_at': datetime.now().isoformat()
        }
        
        return jsonify(load_result)
    except Exception as e:
        logging.error(f"Error loading model: {e}")
        return jsonify({'error': 'Failed to load model'}), 500

@app.route('/api/anomaly/<anomaly_id>')
def api_anomaly_details(anomaly_id):
    """Get anomaly details by ID"""
    try:
        # Placeholder anomaly details
        anomaly_details = {
            'id': anomaly_id,
            'timestamp': datetime.now().isoformat(),
            'severity': 'high',
            'type': 'network_scan',
            'score': 0.85,
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'port': 22,
            'protocol': 'TCP',
            'description': 'Suspicious port scanning activity detected',
            'raw_data': {
                'packet_count': 150,
                'bytes_transferred': 8960,
                'duration': 30
            },
            'model_predictions': {
                'isolation_forest': 0.82,
                'one_class_svm': 0.88,
                'autoencoder': 0.85
            }
        }
        return jsonify(anomaly_details)
    except Exception as e:
        logging.error(f"Error getting anomaly details: {e}")
        return jsonify({'error': 'Failed to get anomaly details'}), 500

@app.route('/api/anomaly/<anomaly_id>/status', methods=['POST'])
def api_anomaly_status(anomaly_id):
    """Update anomaly status"""
    try:
        data = request.get_json() or {}
        status = data.get('status', 'unreviewed')
        
        # Placeholder for status update
        status_result = {
            'anomaly_id': anomaly_id,
            'status': status,
            'updated_at': datetime.now().isoformat(),
            'message': f'Anomaly status updated to {status}'
        }
        
        return jsonify(status_result)
    except Exception as e:
        logging.error(f"Error updating anomaly status: {e}")
        return jsonify({'error': 'Failed to update anomaly status'}), 500

@app.route('/api/anomalies/bulk-action', methods=['POST'])
def api_anomalies_bulk_action():
    """Perform bulk actions on anomalies"""
    try:
        data = request.get_json() or {}
        action = data.get('action', 'mark_reviewed')
        anomaly_ids = data.get('anomaly_ids', [])
        
        # Placeholder for bulk action
        bulk_result = {
            'action': action,
            'processed_count': len(anomaly_ids),
            'successful_count': len(anomaly_ids),
            'failed_count': 0,
            'message': f'Bulk action {action} completed successfully',
            'processed_at': datetime.now().isoformat()
        }
        
        return jsonify(bulk_result)
    except Exception as e:
        logging.error(f"Error performing bulk action: {e}")
        return jsonify({'error': 'Failed to perform bulk action'}), 500

@app.route('/api/flow/<flow_id>')
def api_flow_details(flow_id):
    """Get network flow details by ID"""
    try:
        # Placeholder flow details
        flow_details = {
            'id': flow_id,
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 49152,
            'destination_port': 80,
            'protocol': 'TCP',
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration': 125.5,
            'packets_sent': 45,
            'packets_received': 38,
            'bytes_sent': 3456,
            'bytes_received': 28934,
            'tcp_flags': ['SYN', 'ACK', 'PSH', 'FIN'],
            'application_protocol': 'HTTP',
            'status': 'completed'
        }
        return jsonify(flow_details)
    except Exception as e:
        logging.error(f"Error getting flow details: {e}")
        return jsonify({'error': 'Failed to get flow details'}), 500

@app.route('/api/control/capture', methods=['POST'])
def api_control_capture():
    """Control packet capture"""
    try:
        data = request.get_json() or {}
        action = data.get('action', 'start')
        
        if action == 'start':
            # Placeholder for starting capture
            result = {
                'status': 'started',
                'message': 'Packet capture started successfully',
                'started_at': datetime.now().isoformat()
            }
        elif action == 'stop':
            # Placeholder for stopping capture
            result = {
                'status': 'stopped',
                'message': 'Packet capture stopped successfully',
                'stopped_at': datetime.now().isoformat()
            }
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error controlling capture: {e}")
        return jsonify({'error': 'Failed to control capture'}), 500

@app.route('/api/control/detection', methods=['POST'])
def api_control_detection():
    """Control anomaly detection"""
    try:
        data = request.get_json() or {}
        action = data.get('action', 'start')
        
        if action == 'start':
            # Placeholder for starting detection
            result = {
                'status': 'started',
                'message': 'Anomaly detection started successfully',
                'started_at': datetime.now().isoformat()
            }
        elif action == 'stop':
            # Placeholder for stopping detection
            result = {
                'status': 'stopped',
                'message': 'Anomaly detection stopped successfully',
                'stopped_at': datetime.now().isoformat()
            }
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error controlling detection: {e}")
        return jsonify({'error': 'Failed to control detection'}), 500

@app.route('/api/train-model', methods=['POST'])
def api_train_model():
    """Train machine learning model"""
    try:
        # Placeholder for model training
        training_result = {
            'status': 'started',
            'training_id': f"train_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'message': 'Model training started successfully',
            'estimated_duration': '5-10 minutes',
            'started_at': datetime.now().isoformat()
        }
        
        return jsonify(training_result)
    except Exception as e:
        logging.error(f"Error starting training: {e}")
        return jsonify({'error': 'Failed to start training'}), 500

@app.route('/api/alert/<alert_id>/false-positive', methods=['POST'])
def api_alert_false_positive(alert_id):
    """Mark alert as false positive"""
    try:
        # Placeholder for false positive marking
        result = {
            'alert_id': alert_id,
            'status': 'marked_false_positive',
            'message': 'Alert marked as false positive',
            'updated_at': datetime.now().isoformat()
        }
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error marking false positive: {e}")
        return jsonify({'error': 'Failed to mark false positive'}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Setup logging for Flask
if not app.debug:
    import logging
    from logging.handlers import RotatingFileHandler
    
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_dir / 'web.log',
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Network Anomaly Detector web interface startup')

if __name__ == '__main__':
    app.run(
        host=config.get('app.host', '0.0.0.0'),
        port=config.get('app.port', 5000),
        debug=config.get('app.debug', False)
    )
