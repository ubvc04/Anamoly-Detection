# 🌐 Live Network Packet Capture Dashboard

A real-time network monitoring system that captures and displays live network packets with comprehensive protocol detection through an interactive web dashboard.

## ✨ Features

- **🔴 Live Packet Capture**: Real-time packet monitoring using Scapy with Npcap support
- **🔍 Protocol Detection**: Automatic detection of TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS and more
- **📊 Live Web Dashboard**: Interactive real-time dashboard showing captured packets
- **🖥️ Multiple Interface Support**: Capture from any available network interface
- **📈 Statistics Tracking**: Real-time packet count, protocol distribution, and capture metrics
- **🎨 Modern UI**: Clean, responsive design with auto-refresh capabilities
- **⚡ Instant Control**: Easy capture start/stop from the web interface

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Npcap (for Windows) - Download from https://npcap.com/
- Administrator privileges for packet capture

### Installation & Run

1. **Install dependencies**:
   ```bash
   pip install scapy flask
   ```

2. **Run the application**:
   ```bash
   python simple_app.py
   ```

3. **Access the dashboard**:
   Open your browser and go to `http://127.0.0.1:5001`

## 🖼️ Dashboard Features

- **📡 Live Packet Stream**: Real-time table showing captured packets with full protocol details
- **📊 Statistics Cards**: Total packets, packets per second, protocol types, and capture time
- **🎨 Protocol Detection**: Color-coded protocols (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS)
- **🔄 Auto Refresh**: Automatic updates every 2 seconds
- **📱 Responsive Design**: Works on desktop and mobile devices

## 🛠️ File Structure

```
├── simple_app.py              # Main Flask application
├── live_packet_capture.py     # Live packet capture engine
├── templates/
│   └── live_dashboard.html    # Web dashboard template
└── README.md                  # This file
```

## 🎯 Usage

1. **Start the application** - Run `python simple_app.py`
2. **Open the dashboard** - Navigate to `http://127.0.0.1:5001`
3. **View live packets** - The system auto-starts capture and displays packets in real-time
4. **Control capture** - Use Start/Stop buttons to control packet capture
5. **Monitor statistics** - View real-time statistics including packet counts and protocol distribution

## 📋 Protocol Support

The system automatically detects and displays the following protocols:

- **TCP**: HTTP, HTTPS, SSH, FTP, SMTP, etc.
- **UDP**: DNS, DHCP, NTP, SNMP, etc.
- **ICMP**: Ping, traceroute, network diagnostics
- **ARP**: Address resolution protocol
- **DNS**: Domain name resolution queries and responses

## 🔧 Technical Details

- **Backend**: Python Flask web framework
- **Packet Capture**: Scapy library with Npcap driver
- **Frontend**: HTML5 with vanilla JavaScript
- **Real-time Updates**: Auto-refresh every 2 seconds
- **Data Storage**: In-memory packet buffer (configurable size)

## 🚀 Advanced Features

- **Multi-interface support**: Capture from specific network interfaces
- **Packet filtering**: Protocol-based filtering and display
- **Statistics tracking**: Real-time performance metrics
- **Responsive UI**: Mobile-friendly dashboard
- **Error handling**: Graceful error handling and recovery

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

**Live Network Packet Capture Dashboard** - Monitor your network traffic in real-time! 🚀
