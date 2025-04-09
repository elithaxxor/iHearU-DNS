# 👁️ iHearU-DNS: Web Interface

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.x"/>
  <img src="https://img.shields.io/badge/DNS-Monitoring-orange?style=for-the-badge&logo=cloudflare&logoColor=white" alt="DNS Monitoring"/>
  <img src="https://img.shields.io/badge/Security-Tools-red?style=for-the-badge&logo=shield&logoColor=white" alt="Security Tools"/>
</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/ihearudns-logo.png" alt="iHearU-DNS Logo" width="300"/>
</p>

> 🔍 **iHearU-DNS** is an advanced DNS traffic analysis tool with a sleek web interface, designed for security professionals to detect and monitor anomalous network activity.

---

## 📋 Table of Contents

- [✨ Overview](#-overview)
- [🚀 Features](#-features)
- [🛠️ Installation](#️-installation)
- [🎮 Usage](#-usage)
- [🖥️ Web Interface](#️-web-interface)
- [📊 Data Visualization](#-data-visualization)
- [🔐 Security Considerations](#-security-considerations)
- [⚙️ Configuration Options](#️-configuration-options)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## ✨ Overview

**iHearU-DNS** (eyeDNSu-web) is a powerful web-based interface for DNS traffic monitoring and analysis. This tool captures, processes, and visualizes DNS queries in real-time, helping security professionals identify potential data exfiltration, command and control (C2) traffic, or other suspicious network activities.

<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/dashboard-screenshot.png" alt="Dashboard Screenshot" width="800"/>
</p>

The web interface provides an intuitive visualization of:
- 📈 DNS query patterns
- 🔤 Domain frequency analysis
- ⏱️ Time-based activity monitoring
- 🔍 Anomaly detection highlighting

---

## 🚀 Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| 🕵️ **Real-time DNS Monitoring** | Captures and displays DNS traffic as it happens |
| 🧩 **Pattern Recognition** | Identifies unusual query patterns that may indicate data exfiltration |
| 📱 **Responsive Web UI** | Clean interface that works on desktop and mobile devices |
| 📊 **Interactive Charts** | Visual representations of DNS activity with drill-down capabilities |
| 🔔 **Alert System** | Notifications for suspicious activity based on configurable thresholds |
| 🔄 **Live Updates** | Auto-refreshing data without page reloads |
| 📦 **Export Capabilities** | Save analysis data as CSV, JSON, or PDF reports |
| 🔒 **Secure Design** | HTTPS support and authentication options |

### Analysis Tools

- **Domain Length Analysis**: Flags unusually long subdomains which could indicate encoded data
- **Entropy Calculation**: Measures randomness in domain names to detect algorithmically generated domains
- **Query Frequency Detection**: Identifies domains with abnormal query patterns
- **Historical Comparison**: Compares current traffic with baseline patterns

---

## 🛠️ Installation

### Prerequisites

- Python 3.6 or higher
- Flask framework
- Scapy for packet capture
- Modern web browser
- Root/Administrator privileges (for packet capture)

### Step-by-Step Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/elithaxxor/iHearU-DNS.git
   cd iHearU-DNS
   ```

2. **Install required packages**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your settings**:
   ```bash
   cp config.example.py config.py
   # Edit config.py with your preferred settings
   ```

4. **Run with appropriate privileges**:
   ```bash
   sudo python eyeDNSu-web.py
   ```

5. **Access the web interface**:
   ```
   Open your browser and navigate to http://localhost:5000
   ```

---

## 🎮 Usage

### Starting the Application

```bash
sudo python eyeDNSu-web.py [options]
```

Available options:
- `--interface INTERFACE`: Network interface to monitor (default: auto-detect)
- `--port PORT`: Web server port (default: 5000)
- `--debug`: Enable debug mode
- `--no-capture`: Run web interface without packet capture (for viewing previous results)

### Basic Workflow

1. 🚀 **Launch the application** with appropriate privileges
2. 🔍 **Select network interface** from the dropdown menu
3. ▶️ **Start monitoring** by clicking the "Begin Monitoring" button
4. 📊 **View real-time statistics** in the dashboard panels
5. 🔎 **Investigate anomalies** by clicking on highlighted entries
6. 📑 **Export reports** as needed for further analysis or documentation

<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/workflow.gif" alt="Workflow Animation" width="700"/>
</p>

---

## 🖥️ Web Interface

The `eyeDNSu-web.py` script creates a Flask-based web application that:

1. **Captures DNS Packets**: Uses Scapy to sniff DNS traffic on the specified interface
2. **Processes Queries**: Extracts relevant information from each DNS query
3. **Analyzes Patterns**: Applies various algorithms to detect anomalies
4. **Renders Visualizations**: Creates interactive charts and tables
5. **Provides Controls**: Offers filtering, searching, and export functionality

```python
# Key components from the code:
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

@app.route('/')
def index():
    """Render the main dashboard"""
    return render_template('index.html', stats=get_current_stats())

@app.route('/api/dns-data')
def get_dns_data():
    """API endpoint for refreshing DNS data"""
    return jsonify(process_dns_data())
```

### Interface Components

- **Header Panel**: Navigation, controls, and system status
- **Summary Dashboard**: Key metrics and threat indicators
- **Query Log**: Detailed list of captured DNS queries
- **Analysis Tabs**: Different views for analyzing the data
- **Visualization Area**: Interactive charts and graphs
- **Alert Panel**: Notifications about detected anomalies

---

## 📊 Data Visualization

iHearU-DNS leverages several visualization techniques to make DNS traffic patterns more understandable:

### Chart Types

- **Time Series Charts**: View query volume over time
- **Domain Cloud**: Visual representation of domain frequency
- **Heatmaps**: Identify periods of unusual activity
- **Network Graphs**: Visualize relationships between domains and IP addresses

<details>
<summary>📈 Click to see visualization examples</summary>

#### Query Volume Timeline
<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/timeline-chart.png" alt="Query Timeline" width="600"/>
</p>

#### Domain Length Distribution
<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/domain-length.png" alt="Domain Length Chart" width="600"/>
</p>

#### Query Type Distribution
<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/query-types.png" alt="Query Types Chart" width="600"/>
</p>
</details>

### Interactive Elements

All charts include:
- **Zoom capabilities**: Focus on specific time periods
- **Tooltip details**: Get additional information on hover
- **Click-through analysis**: Drill down into specific data points
- **Filtering options**: Refine the displayed information

---

## 🔐 Security Considerations

### Permissions

⚠️ **Note**: iHearU-DNS requires root/administrator privileges to capture network traffic.

```bash
# Always run with appropriate privileges
sudo python eyeDNSu-web.py
```

### Secure Deployment

For production environments:

1. **Use HTTPS**: Configure with proper SSL certificates
   ```python
   # In the code:
   if __name__ == '__main__':
       context = ('cert.pem', 'key.pem')  # Your certificate files
       app.run(host='0.0.0.0', port=5000, ssl_context=context)
   ```

2. **Implement Authentication**: Add user authentication for access control
   ```python
   # Basic auth example in Flask:
   from flask_httpauth import HTTPBasicAuth
   auth = HTTPBasicAuth()
   
   @auth.verify_password
   def verify_password(username, password):
       # Verify against your user database
       return username == 'admin' and password == 'secret'
   
   @app.route('/')
   @auth.login_required
   def index():
       return render_template('index.html')
   ```

3. **Restrict Access**: Limit the application to local network or VPN access

---

## ⚙️ Configuration Options

iHearU-DNS can be customized through the `config.py` file:

```python
# Example configuration options
CONFIG = {
    # Network Settings
    'DEFAULT_INTERFACE': 'eth0',
    'CAPTURE_FILTER': 'udp port 53',
    
    # Analysis Parameters
    'ENTROPY_THRESHOLD': 4.2,
    'ABNORMAL_LENGTH_THRESHOLD': 50,
    'QUERY_FREQUENCY_THRESHOLD': 10,
    
    # Web Interface
    'REFRESH_INTERVAL': 5,  # seconds
    'MAX_DISPLAYED_QUERIES': 1000,
    'ENABLE_HTTPS': False,
    
    # Alert Settings
    'ENABLE_ALERTS': True,
    'ALERT_METHODS': ['web', 'email'],
    'EMAIL_RECIPIENT': 'admin@example.com',
}
```

---

## 🤝 Contributing

Contributions to iHearU-DNS are welcome! Here's how you can help:

1. **Fork the repository** on GitHub
2. **Create a new branch** for your feature or bugfix
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes** and test thoroughly
4. **Commit your changes** with clear, descriptive messages
   ```bash
   git commit -m "Add amazing feature with detailed description"
   ```
5. **Push to your branch**
   ```bash
   git push origin feature/amazing-feature
   ```
6. **Create a Pull Request** with a comprehensive description of changes

### Development Guidelines

- Follow PEP 8 style guidelines
- Write tests for new features
- Update documentation to reflect changes
- Maintain compatibility with Python 3.6+

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2023 elithaxxor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

---

<p align="center">
  <a href="https://github.com/elithaxxor/iHearU-DNS">
    <img src="https://img.shields.io/github/stars/elithaxxor/iHearU-DNS?style=social" alt="Stars"/>
  </a>
  <a href="https://github.com/elithaxxor/iHearU-DNS/fork">
    <img src="https://img.shields.io/github/forks/elithaxxor/iHearU-DNS?style=social" alt="Forks"/>
  </a>
</p>

<p align="center">
  <img src="https://visitor-badge.laobi.icu/badge?page_id=elithaxxor.iHearU-DNS" alt="Visitors"/>
</p>

<p align="center">
  Made with ❤️ by <a href="https://github.com/elithaxxor">elithaxxor</a>
</p>

> 🔍 "Listen to what your DNS is telling you"
