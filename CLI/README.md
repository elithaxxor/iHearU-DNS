# 👁️‍🗨️ iHearU-DNS: CLI Edition

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.x"/>
  <img src="https://img.shields.io/badge/DNS-Monitor-orange?style=for-the-badge&logo=cloudflare&logoColor=white" alt="DNS Monitor"/>
  <img src="https://img.shields.io/badge/Network-Security-red?style=for-the-badge&logo=wireshark&logoColor=white" alt="Network Security"/>
  <img src="https://img.shields.io/badge/CLI-Tool-green?style=for-the-badge&logo=gnubash&logoColor=white" alt="CLI Tool"/>
</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/ihearudns-cli-logo.png" alt="iHearU-DNS CLI Logo" width="300"/>
</p>

> 🔍 **A powerful command-line DNS traffic analyzer for detecting exfiltration attempts, suspicious domains, and network anomalies**

---

## 📋 Table of Contents

- [🌟 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [🚀 Installation](#-installation)
- [🖥️ Usage](#️-usage)
- [🔍 Detection Methods](#-detection-methods)
- [📊 Output Formats](#-output-formats)
- [⚙️ Advanced Configuration](#️-advanced-configuration)
- [👨‍💻 Example Scenarios](#-example-scenarios)
- [📝 Logging](#-logging)
- [🔄 Integrations](#-integrations)
- [🛡️ Security Considerations](#️-security-considerations)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## 🌟 Overview

**iHearU-DNS CLI** (`eyeDNSu.py`) is a sophisticated command-line tool that monitors and analyzes DNS traffic in real-time. Designed for security professionals and network administrators, it helps detect suspicious DNS activities that might indicate data exfiltration, command and control communication, or DNS tunneling attempts.

<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/cli-terminal-demo.gif" alt="CLI Demo" width="700"/>
</p>

Unlike traditional network monitoring tools, iHearU-DNS specializes in:

- 🔎 **DNS-specific pattern analysis**
- 📏 **Domain length and entropy calculations**
- 🔄 **Query frequency monitoring**
- 📈 **Statistical anomaly detection**
- 🛑 **Real-time alerts and blocks**

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔄 **Live DNS Capture** | Monitors DNS queries in real-time using Python's Scapy |
| 📊 **Pattern Analysis** | Analyzes query patterns, frequencies, and anomalies |
| 🧮 **Shannon Entropy** | Calculates entropy scores to detect algorithmically generated domains |
| 📏 **Length Analysis** | Flags unusually long domain names that may contain encoded data |
| 🔔 **Alert System** | Configurable alerts for suspicious activities |
| 📝 **Detailed Logging** | Comprehensive logging with multiple verbosity levels |
| 📂 **Output Formats** | Export results as JSON, CSV, or plain text |
| 🧩 **Modular Design** | Easily extendable with custom detection modules |
| 🔄 **Auto-Update** | Optional integration with threat intelligence feeds |
| 🐧 **Cross-Platform** | Works on Linux, macOS, and Windows (with admin privileges) |

---

## 🚀 Installation

### Prerequisites

- Python 3.6+
- Scapy library
- Admin/root privileges (required for packet capture)
- Colorama (for terminal output formatting)
- tqdm (for progress indicators)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/elithaxxor/iHearU-DNS.git
   cd iHearU-DNS/CLI
   ```

2. **Install required packages**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   sudo python eyeDNSu.py --version
   ```

<details>
<summary>📦 <b>Dependencies explained</b></summary>

```
scapy>=2.4.5      # For network packet capture and analysis
colorama>=0.4.4   # For colored terminal output
argparse>=1.4.0   # For command-line argument parsing
tqdm>=4.62.3      # For progress bars
pyyaml>=6.0       # For configuration file parsing
python-dateutil   # For date/time handling
```
</details>

---

## 🖥️ Usage

### Basic Command

```bash
sudo python eyeDNSu.py
```

### Command-Line Options

```bash
sudo python eyeDNSu.py [OPTIONS]
```

<details>
<summary>🔧 <b>Available options</b></summary>

| Option | Description |
|--------|-------------|
| `-i, --interface INTERFACE` | Network interface to monitor (default: auto-detect) |
| `-f, --filter FILTER` | Custom BPF filter for packet capture |
| `-o, --output FILE` | Output file for results |
| `-t, --threshold FLOAT` | Entropy threshold for alerts (default: 4.5) |
| `-l, --log-level {DEBUG,INFO,WARNING,ERROR}` | Set logging level |
| `-c, --config FILE` | Custom configuration file |
| `-n, --no-color` | Disable colored output |
| `-q, --quiet` | Suppress all output except alerts |
| `-v, --verbose` | Increase output verbosity |
| `-w, --whitelist FILE` | File containing whitelisted domains |
| `-b, --blacklist FILE` | File containing blacklisted domains |
| `-d, --duration SECONDS` | Duration to run in seconds (default: until Ctrl+C) |
| `--json` | Output in JSON format |
| `--csv` | Output in CSV format |
| `--version` | Show version information and exit |
</details>

### Example Commands

```bash
# Basic monitoring on default interface
sudo python eyeDNSu.py

# Monitor specific interface with custom entropy threshold
sudo python eyeDNSu.py -i eth0 -t 4.2

# Output to JSON file with increased verbosity
sudo python eyeDNSu.py -o results.json --json -v

# Use custom whitelist and run for 10 minutes
sudo python eyeDNSu.py -w whitelist.txt -d 600

# Advanced filtering with custom BPF filter
sudo python eyeDNSu.py -f "udp port 53 and not host 8.8.8.8"
```

---

## 🔍 Detection Methods

iHearU-DNS employs multiple detection strategies to identify suspicious DNS activities:

### 1. 🔤 Shannon Entropy Analysis

```python
def calculate_entropy(domain):
    """Calculate Shannon entropy of domain name to detect algorithmically generated domains."""
    # Code from eyeDNSu.py that calculates entropy
```

<p align="center">
  <img src="https://raw.githubusercontent.com/elithaxxor/iHearU-DNS/main/assets/entropy-chart.png" alt="Entropy Analysis" width="500"/>
</p>

> 💡 **What it catches**: Domain generation algorithms (DGAs) commonly used by malware

### 2. 📏 Domain Length Analysis

Flags domains with unusually long subdomains or total length:

```python
def analyze_domain_length(domain):
    """Check if domain length exceeds normal parameters."""
    # Length analysis implementation
```

> 💡 **What it catches**: Data exfiltration via DNS queries, which often embed encoded data in lengthy subdomains

### 3. 🔄 Query Frequency Detection

```python
def check_query_frequency(domain):
    """Monitor frequency of queries to detect abnormal patterns."""
    # Frequency detection logic
```

> 💡 **What it catches**: Command and control beaconing or DNS tunneling with frequent, repeated queries

### 4. 📋 Suspicious TLD Monitoring

```python
def check_suspicious_tld(domain):
    """Check if domain uses suspicious or uncommon TLDs."""
    # TLD checking implementation
```

> 💡 **What it catches**: Phishing domains using non-standard or recently created TLDs

---

## 📊 Output Formats

### Terminal Output

The CLI provides rich, colorized terminal output showing:

- 🟢 Normal DNS queries (green)
- 🟡 Suspicious queries (yellow)
- 🔴 Highly suspicious queries (red)
- ⚪ Informational messages (white)

```
[2023-04-09 15:42:17] 🟢 DNS Query: example.com (192.168.1.5)
[2023-04-09 15:42:19] 🟡 Suspicious Query: a23xkvp9d0sjw92.dynamic.example.net (192.168.1.10) [Entropy: 4.7]
[2023-04-09 15:42:22] 🔴 ALERT: Possible data exfiltration via e8sn7a9wbgdkfp2j4c0vx5l6z8h3uqio17tmyr.evil.com (192.168.1.15) [Entropy: 5.2]
```

### File Exports

iHearU-DNS can export data in multiple formats:

#### JSON Output
```json
{
  "timestamp": "2023-04-09T15:42:22",
  "source_ip": "192.168.1.15",
  "query": "e8sn7a9wbgdkfp2j4c0vx5l6z8h3uqio17tmyr.evil.com",
  "query_type": "A",
  "entropy": 5.2,
  "length": 42,
  "risk_level": "high",
  "reason": "high entropy, excessive length"
}
```

#### CSV Output
```
timestamp,source_ip,query,query_type,entropy,length,risk_level,reason
2023-04-09T15:42:22,192.168.1.15,e8sn7a9wbgdkfp2j4c0vx5l6z8h3uqio17tmyr.evil.com,A,5.2,42,high,"high entropy, excessive length"
```

---

## ⚙️ Advanced Configuration

### Configuration File

iHearU-DNS supports YAML configuration files for advanced settings:

```yaml
# config.yaml
network:
  interface: eth0
  filter: "udp port 53"
  timeout: 120

detection:
  entropy_threshold: 4.5
  max_domain_length: 50
  max_subdomain_length: 30
  query_frequency_threshold: 10
  time_window: 60

alerts:
  enabled: true
  log_file: "/var/log/ihearudns.log"
  syslog: true
  email:
    enabled: false
    smtp_server: "smtp.example.com"
    from: "alerts@example.com"
    to: "admin@example.com"

output:
  format: "json"
  file: "dns_events.json"
  append: true
```

Use your configuration file with:

```bash
sudo python eyeDNSu.py -c config.yaml
```

### Custom Detection Rules

Create your own detection modules by extending the base classes:

```python
# custom_detector.py
from eyeDNSu import BaseDetector

class MyCustomDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="Custom Pattern Detector")
        
    def analyze(self, domain, query_type, source_ip):
        # Your custom detection logic here
        if "pattern" in domain:
            return True, "Matched custom pattern", "medium"
        return False, "", "low"
```

---

## 👨‍💻 Example Scenarios

### Scenario 1: Basic Network Monitoring

```bash
sudo python eyeDNSu.py -v
```

Perfect for routine monitoring of your network to establish baseline DNS activity.

### Scenario 2: Security Incident Response

```bash
sudo python eyeDNSu.py -i eth0 -o incident_evidence.json --json -v -t 4.0
```

When responding to a security incident, collect comprehensive evidence with lower thresholds to catch more suspicious activity.

### Scenario 3: Continuous Monitoring with Whitelist

```bash
sudo python eyeDNSu.py -w trusted_domains.txt -l WARNING
```

For ongoing monitoring of production environments, whitelist your known-good domains to reduce false positives.

### Scenario 4: Educational Demonstration

```bash
sudo python eyeDNSu.py -d 300 -v --csv -o dns_demo.csv
```

Perfect for classroom demonstrations or training sessions with a 5-minute capture to CSV.

---

## 📝 Logging

iHearU-DNS provides comprehensive logging capabilities:

### Log Levels

- **DEBUG**: Detailed debugging information
- **INFO**: General operational events
- **WARNING**: Potential issues or suspicious activities
- **ERROR**: Error conditions
- **CRITICAL**: Critical errors requiring immediate attention

### Log Output Example

```
2023-04-09 15:42:15 [INFO] iHearU-DNS started on interface eth0
2023-04-09 15:42:17 [DEBUG] Processing query: example.com from 192.168.1.5
2023-04-09 15:42:19 [WARNING] Suspicious domain detected: a23xkvp9d0sjw92.dynamic.example.net (Entropy: 4.7)
2023-04-09 15:42:22 [CRITICAL] Possible data exfiltration detected: e8sn7a9wbgdkfp2j4c0vx5l6z8h3uqio17tmyr.evil.com
```

---

## 🔄 Integrations

iHearU-DNS can integrate with various security tools and systems:

### 1. 🛡️ Threat Intelligence Feeds

```bash
sudo python eyeDNSu.py --threat-intel-feed https://example.com/malicious_domains.txt
```

### 2. 📊 SIEM Integration

Output to JSON or syslog for easy integration with Security Information and Event Management systems:

```bash
sudo python eyeDNSu.py --syslog --facility local5
```

### 3. 🤖 Automation Scripts

Trigger custom scripts on detection:

```bash
sudo python eyeDNSu.py --exec-on-detect "/path/to/script.sh {domain} {ip}"
```

---

## 🛡️ Security Considerations

### Required Privileges

⚠️ iHearU-DNS requires root/administrator privileges to capture network packets. Run with appropriate security precautions:

```bash
sudo python eyeDNSu.py
```

### Ethical Usage

⚠️ This tool should only be used on networks you own or have explicit permission to monitor. Unauthorized DNS monitoring may violate:

- Privacy laws
- Terms of service agreements
- Corporate security policies
- Local, state, or federal laws

### Data Handling

Be mindful of captured data, which may contain:
- Personal information
- Internal domain structures
- Network architecture details

---
