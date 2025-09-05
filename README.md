# 🛡️ Network Anomaly Detection System

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.6+-red.svg)](https://scapy.net/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20TensorFlow-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](https://github.com/ubvc04/Anamoly-Detection)

A **real-time network anomaly detection system** powered by machine learning that monitors network traffic, detects suspicious activities, and provides comprehensive analysis through an intuitive web dashboard.

## 🚀 Features

### 🔍 **Real-Time Network Monitoring**
- **Live Packet Capture**: Captures network packets in real-time using Scapy
- **Multi-Protocol Support**: TCP, UDP, ICMP, and more
- **Interface Detection**: Automatic network interface discovery
- **Traffic Analysis**: Deep packet inspection and feature extraction

### 🤖 **Machine Learning Engine**
- **Anomaly Detection**: Advanced ML algorithms for identifying suspicious patterns
- **Baseline Collection**: Automated normal traffic profiling
- **Multiple Models**: Support for Isolation Forest, One-Class SVM, and more
- **Feature Engineering**: 20+ network features including flow statistics, timing patterns, and protocol analysis

### 📊 **Interactive Web Dashboard**
- **Real-Time Visualizations**: Live charts and graphs using Plotly
- **Network Traffic Overview**: Comprehensive traffic statistics and trends
- **Anomaly Timeline**: Historical view of detected anomalies
- **Model Performance**: ML model metrics and feature importance
- **System Monitoring**: CPU, memory, and network utilization

### ⚡ **Real-Time Processing**
- **Stream Processing**: Real-time packet analysis pipeline
- **Live Capture API**: RESTful endpoints for packet capture control
- **WebSocket Integration**: Real-time data streaming to web interface
- **Background Services**: Multithreaded processing for optimal performance

### 🔧 **Advanced Configuration**
- **Flexible Settings**: Configurable detection thresholds and parameters
- **Model Training**: Custom model training with your network data
- **Alert Management**: Configurable alerting and notification system
- **Data Export**: Export captured data and analysis results

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Interface │◄──►│   Flask Backend  │◄──►│  ML Engine      │
│   (Dashboard)   │    │   (API Server)   │    │  (Detection)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Packet Capture   │
                       │ Service (Scapy)  │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Network Traffic  │
                       │ (Live Packets)   │
                       └──────────────────┘
```

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10/11, Linux, macOS
- **Python**: 3.11 or higher
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Storage**: 2GB free disk space
- **Network**: Administrative privileges for packet capture

### Dependencies
- **Flask 3.0+**: Web framework
- **Scapy 2.6+**: Packet capture and analysis
- **Scikit-learn 1.3+**: Machine learning algorithms
- **TensorFlow 2.15+**: Deep learning models
- **Pandas 2.0+**: Data manipulation
- **NumPy 1.24+**: Numerical computing
- **Plotly 5.17+**: Interactive visualizations

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/ubvc04/Anamoly-Detection.git
cd Anamoly-Detection
```

### 2. Set Up Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure the System
```bash
# Copy configuration template
cp config/config.yaml.example config/config.yaml

# Edit configuration as needed
# Set network interface, detection thresholds, etc.
```

### 5. Run the Application
```bash
# Start the web application
python app.py

# Or use the run script
python run.py
```

### 6. Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

## 📖 Usage Guide

### 🎯 **Getting Started**

1. **Initial Setup**
   - Navigate to the **Settings** page to configure your network interface
   - Set detection thresholds and sensitivity levels
   - Configure alert preferences

2. **Baseline Collection**
   - Go to the **Baseline** page
   - Click "Start Baseline Collection" to profile normal network behavior
   - Let the system collect data for at least 30 minutes for optimal results

3. **Start Detection**
   - Once baseline is collected, enable real-time detection
   - Monitor the **Dashboard** for live statistics and alerts
   - Review detected anomalies in the **Anomalies** section

### 🖥️ **Dashboard Overview**

#### Main Dashboard
- **📈 Real-time Metrics**: Live network statistics and performance indicators
- **🚨 Alert Summary**: Recent anomalies and their severity levels
- **📊 Traffic Visualization**: Interactive charts showing network patterns
- **⚡ System Status**: Current capture and detection status

#### Network Traffic Page
- **🌐 Traffic Analysis**: Detailed breakdown of network protocols and flows
- **📈 Bandwidth Usage**: Real-time and historical bandwidth monitoring
- **🔍 Packet Details**: Deep dive into individual packet characteristics

#### Anomalies Page
- **🚨 Anomaly Timeline**: Chronological view of detected anomalies
- **📋 Detailed Analysis**: In-depth analysis of each detected anomaly
- **✅ False Positive Management**: Mark and manage false positives

#### Models Page
- **🤖 Model Performance**: Accuracy metrics and performance statistics
- **📊 Feature Importance**: Understanding which features contribute to detection
- **⚙️ Model Training**: Retrain models with new data

### 🔧 **API Endpoints**

The system provides comprehensive REST API endpoints:

#### Capture Control
```bash
# Start packet capture
POST /api/capture/start

# Stop packet capture
POST /api/capture/stop

# Get capture status
GET /api/capture/status

# Get captured packets
GET /api/capture/packets
```

#### ML Model Control
```bash
# Get ML model status
GET /api/ml/status

# Start baseline collection
POST /api/ml/baseline/start

# Train model
POST /api/ml/train

# Get model metrics
GET /api/models/performance
```

#### Statistics and Monitoring
```bash
# Get system statistics
GET /api/statistics

# Get real-time alerts
GET /api/alerts

# Get traffic flows
GET /api/flows
```

## 🔧 Configuration

### Network Interface Configuration
```yaml
network:
  interface: "auto"  # Auto-detect or specify interface name
  promiscuous_mode: true
  buffer_size: 65535
```

### Detection Parameters
```yaml
detection:
  sensitivity: 0.1  # Lower = more sensitive
  baseline_duration: 1800  # 30 minutes in seconds
  feature_window: 60  # Feature calculation window in seconds
  alert_threshold: 0.8
```

### Machine Learning Settings
```yaml
ml_models:
  isolation_forest:
    contamination: 0.1
    n_estimators: 100
  one_class_svm:
    nu: 0.1
    kernel: "rbf"
```

## 🧪 Testing

### Run Unit Tests
```bash
# Run all tests
python -m pytest tests/

# Run specific test files
python test_basic.py
python test_core.py
python test_packet_capture.py
```

### Test Packet Capture
```bash
# Test live packet capture (requires admin privileges)
python -c "
from packet_capture_service import PacketCaptureService
service = PacketCaptureService()
result = service.test_capture(count=10, timeout=30)
print(f'Captured {len(result)} packets')
"
```

## 🛠️ Development

### Project Structure
```
Anamoly-Detection/
├── 📁 app/                     # Additional app modules
├── 📁 config/                  # Configuration files
│   ├── config.py              # Configuration manager
│   └── config.yaml            # Main configuration
├── 📁 data/                   # Data storage
├── 📁 logs/                   # Application logs
├── 📁 models/                 # Trained ML models
├── 📁 static/                 # Web assets (CSS, JS)
├── 📁 templates/              # HTML templates
├── 📁 tests/                  # Unit tests
├── 📄 app.py                  # Main Flask application
├── 📄 packet_capture_service.py # Real-time packet capture
├── 📄 ml_model.py             # Machine learning engine
├── 📄 network_capture.py      # Network interface handling
├── 📄 detector.py             # Anomaly detection logic
├── 📄 feature_extraction.py   # Feature engineering
├── 📄 database.py             # Database operations
├── 📄 background_service.py   # Background processing
└── 📄 requirements.txt        # Python dependencies
```

### Key Components

#### 🔍 **Packet Capture Service** (`packet_capture_service.py`)
- Real-time packet capture using Scapy
- Multi-threaded processing for optimal performance
- Feature extraction and ML integration
- RESTful API for capture control

#### 🤖 **ML Engine** (`ml_model.py`)
- Multiple anomaly detection algorithms
- Baseline profiling and model training
- Real-time prediction and scoring
- Model performance metrics

#### 🌐 **Web Interface** (`app.py`)
- Flask-based web dashboard
- Real-time data visualization
- RESTful API endpoints
- Interactive user interface

#### 📊 **Feature Engineering** (`feature_extraction.py`)
- 20+ network features extraction
- Statistical analysis of traffic patterns
- Protocol-specific feature calculation
- Time-series feature engineering

### Adding New Features

1. **New ML Models**: Add models in `ml_model.py`
2. **Custom Features**: Extend `feature_extraction.py`
3. **Web Pages**: Add templates in `templates/` and routes in `app.py`
4. **API Endpoints**: Add new routes in `app.py`

## 🐛 Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Windows: Run as Administrator
# Linux/macOS: Use sudo or adjust capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
```

#### No Network Interface Found
```bash
# List available interfaces
python -c "
import netifaces
print('Available interfaces:', netifaces.interfaces())
"
```

#### Packet Capture Not Working
- Ensure administrative privileges
- Check firewall settings
- Verify network interface is active
- Install WinPcap/Npcap on Windows

#### ML Model Training Issues
- Ensure sufficient baseline data (minimum 1000 packets)
- Check data quality and feature extraction
- Verify model parameters in configuration

### Debug Mode
```bash
# Enable debug logging
export FLASK_ENV=development
python app.py
```

## 📈 Performance Optimization

### System Performance
- **CPU Usage**: Multi-threaded processing minimizes CPU overhead
- **Memory Management**: Efficient packet buffering and garbage collection
- **Storage**: Configurable data retention and cleanup policies

### Scaling Recommendations
- **Small Networks** (< 100 hosts): Default configuration
- **Medium Networks** (100-1000 hosts): Increase buffer sizes and processing threads
- **Large Networks** (> 1000 hosts): Consider distributed deployment

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints where possible
- Add docstrings for new functions
- Include unit tests for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Flask**: Lightweight web framework
- **Scikit-learn**: Machine learning toolkit
- **Plotly**: Interactive visualization library
- **TensorFlow**: Deep learning framework

## 📞 Support

- **Documentation**: [Wiki](https://github.com/ubvc04/Anamoly-Detection/wiki)
- **Issues**: [GitHub Issues](https://github.com/ubvc04/Anamoly-Detection/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ubvc04/Anamoly-Detection/discussions)

## 🔄 Changelog

### Version 2.0.0 (Current)
- ✅ Real-time packet capture service
- ✅ Advanced ML anomaly detection
- ✅ Interactive web dashboard
- ✅ RESTful API endpoints
- ✅ Multi-threaded processing
- ✅ Comprehensive logging and monitoring

### Version 1.0.0
- ✅ Basic anomaly detection
- ✅ Web interface
- ✅ Configuration management
- ✅ Database integration

---

<div align="center">

**🛡️ Secure your network with intelligent anomaly detection 🛡️**

[⭐ Star this repository](https://github.com/ubvc04/Anamoly-Detection) | [🐛 Report Bug](https://github.com/ubvc04/Anamoly-Detection/issues) | [💡 Request Feature](https://github.com/ubvc04/Anamoly-Detection/issues)

</div>
