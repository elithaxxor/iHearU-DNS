# eyeDNSu: Fake DNS Rerouting and Visualization Server

![DNS Visualization](https://img.shields.io/badge/DNS-Visualization-blue)
![Python](https://img.shields.io/badge/Python-3.6+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Version](https://img.shields.io/badge/Version-1.0.0-orange)

## Overview

**eyeDNSu** is an advanced fake DNS server designed for testing, research, and demonstration purposes. It reroutes DNS queries for configured domains and provides extensive logging and visualization of query data. The server supports both UDP and TCP DNS queries and is built using asynchronous I/O for improved performance.

## Purpose

eyeDNSu is designed to simulate a DNS server that:

- **Reroutes**: Redirects DNS queries for specified domains (e.g., the top 500 visited websites) to a fixed IP address
- **Logs**: Records query details (client IP, domain queried, frequency, etc.) to log files
- **Visualizes**: Generates dynamic visualizations (pie charts, line graphs, heat maps) of the DNS query data
- **Tests & Research**: Acts as a testbed for network research, security testing, and performance benchmarking

## 🌟 Key Features

### DNS Query Handling
- **Protocols**: Supports both UDP and TCP DNS queries
- **Record Types**: Currently handles A records, with extensions for AAAA and MX records
- **Action Modes**:
  - **Log only**: Processes queries normally and logs details
  - **Reroute only**: Ignores configuration and always responds with a fixed IP (e.g., `10.0.0.1`)
  - **Both log and reroute**: Logs the query and returns the fixed reroute IP

### Dynamic Configuration & Caching
- **Dynamic Config Loader**: Loads domain-to-record mappings from a JSON configuration file (`dns_config.json`)
- **Auto-reload**: Supports automatic reloading to reflect configuration changes
- **Response Caching**: Implements an LRU cache with TTL for DNS responses to improve performance

### Visualization Dashboard
- **Data Collection**: Collects query data (timestamps, domains, protocol used) in real time
- **Visualization Types**:
  - **Pie Charts**: Distribution of DNS queries by domain
  - **Line Graphs**: Trends of DNS queries over time
  - **Heat Maps**: Peak usage times by hour of the day
- **Web Interface**: Integrates a Flask web server to display visualizations online

## 📊 Web Dashboard

The project includes a built-in web dashboard for real-time visualization:

- **Flask Integration**: Creates a Flask app with endpoints for different visualization types
- **Concurrent Operation**: When run with the `--flask` flag, the Flask server runs alongside the DNS server
- **Real-time Data**: Uses collected query data to generate up-to-date charts

## 🚀 Getting Started

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/eyeDNSu.git
cd eyeDNSu

# Install dependencies
pip install -r requirements.txt
```

### Usage

Run the DNS server with web dashboard:

```bash
python eyeDNSu-web.py --flask
```

This will start:
- The DNS server on the default port (53)
- The Flask web server on port 5000

### Accessing Visualizations

Once the server is running, access the web dashboard at:

- Main dashboard: `http://localhost:5000/`
- Pie chart: `http://localhost:5000/pie`
- Line graph: `http://localhost:5000/line`
- Heat map: `http://localhost:5000/heat`

## 🧪 Testing

The project includes unit and integration tests to verify functionality:

```bash
# Run the test suite
python -m unittest discover tests
```

## 📋 Configuration

Edit the `dns_config.json` file to configure domain mappings:

```json
{
  "example.com": "192.168.1.10",
  "test.org": "192.168.1.20"
}
```

If a domain is not found in the configuration, the server will return a default IP address (`192.168.1.100`).

## 📝 Logging

The server logs all DNS queries with the following information:
- Client IP address
- Domain queried
- Response sent
- Query frequency

## 🔒 Security Note

This tool is designed for testing, research, and educational purposes only. Using it to intercept or manipulate DNS traffic on networks without proper authorization may violate laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
