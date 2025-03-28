```markdown


	1.	Flask Integration:
	•	A new Flask app is created with endpoints (/, /pie, /line, /heat).
	•	Each endpoint generates a visualization chart (using matplotlib) and returns it as an image (PNG).
	•	The start_flask_server() function launches the Flask app in a separate thread on port 5000.
	2.	Concurrent Operation:
	•	When run with the --flask flag, the Flask server starts alongside the asynchronous DNS server so you can access the online dashboard.
	3.	Visualization Data:
	•	The global list query_records collects query data in real time, which is used to generate the charts.
	4.	Usage:


#### Run the DNS server with:
```bash
	python eyeDNSu-web.py --flask
``

# eyeDNSu: Fake DNS Rerouting and Visualization Server

## Overview

**eyeDNSu** is an advanced fake DNS server designed for testing, research, and demonstration purposes. It reroutes DNS queries for configured domains and provides extensive logging and visualization of query data. The server supports both UDP and TCP DNS queries and is built using asynchronous I/O for improved performance. In addition, it integrates a Flask web server for online access to real-time visualizations.

## Purpose

The primary purpose of eyeDNSu is to simulate a DNS server that:
- **Reroutes**: Redirects DNS queries for specified domains (e.g., the top 500 visited websites) to a fixed IP address.
- **Logs**: Records query details (client IP, domain queried, frequency, etc.) to log files.
- **Visualizes**: Generates dynamic visualizations (pie charts, line graphs, heat maps) of the DNS query data.
- **Tests & Research**: Acts as a testbed for network research, security testing, and performance benchmarking.

## Capabilities

### DNS Query Handling
- **Protocols**: Supports both UDP and TCP DNS queries.
- **Record Types**: Currently handles A records, with extensions for AAAA and MX records.
- **Action Modes**: Provides a configurable action mode:
  - **Log only**: Processes queries normally and logs details.
  - **Reroute only**: Ignores configuration and always responds with a fixed IP (e.g., `10.0.0.1`).
  - **Both log and reroute**: Logs the query and returns the fixed reroute IP.

### Dynamic Configuration & Caching
- **Dynamic Config Loader**: Loads domain-to-record mappings from a JSON configuration file (`dns_config.json`). Supports automatic reloading to reflect changes.
- **Response Caching**: Implements an LRU cache with TTL for DNS responses to improve performance and reduce load.

### Visualization
- **Data Collection**: Collects query data (timestamps, domains, protocol used) in real time.
- **Visualization Options**: Provides multiple visualization methods:
  - **Pie Charts**: Distribution of DNS queries by domain.
  - **Line Graphs**: Trends of DNS queries over time.
  - **Heat Maps**: Peak usage times by hour of the day.
- **Web Dashboard**: Integrates a Flask web server that exposes endpoints to display the visualizations online.

### Testing
- **Unit & Integration Tests**: Includes a suite of tests to verify UDP/TCP query processing and basic server functionality using Python's `unittest` framework.





# Explanation of the `eyeDNSu` File

The file `eyeDNSu` is a Python script that implements a fake DNS server. Here is a detailed explanation of its functionality:

## Logging Configuration:
- The script sets up logging for both UDP and TCP DNS queries. It logs client IP addresses, the DNS queries made, the responses sent, and the frequency of each query.

## Query Tracking:
- The script uses dictionaries to keep track of how many times each client IP has queried each domain.

## Domain-IP Mapping:
- A dictionary (`DOMAIN_IP_MAP`) maps domain names to specific IP addresses. If a queried domain is not found in the dictionary, a default IP address (`192.168.1.100`) is returned.

## DNS Query Handling:
- The script defines two handler classes (`DNSUDPHandler` and `DNSTCPHandler`) to handle DNS queries over UDP and TCP, respectively.
- Each handler parses the DNS query, logs the query details, determines the appropriate IP address to return, and sends back a DNS response with an A record containing that IP address.

## Server Setup:
- In the main block, the script sets up UDP and TCP servers on port 53 (or a custom port if provided via command-line argument).
- It starts the servers and handles incoming DNS queries using separate threads for UDP and TCP.

## Graceful Shutdown:
- The script can be terminated using a keyboard interrupt, which will shut down the servers gracefully.

## Example of Usage:

To run the script, you would use a command like `python3 eyeDNSu` or `python3 eyeDNSu <custom_port>`.
The script will then start listening for DNS queries on the specified port and respond according to the domain-IP mappings defined in the `DOMAIN_IP_MAP` dictionary.

For more detailed information, you can view the file on GitHub.
```



iDNS_CUP
=====================================
Overview


# Explanation of the `eyeDNSu` File

The file `eyeDNSu` is a Python script that implements a fake DNS server. Here is a detailed explanation of its functionality:

## Logging Configuration:
- The script sets up logging for both UDP and TCP DNS queries. It logs client IP addresses, the DNS queries made, the responses sent, and the frequency of each query.

## Query Tracking:
- The script uses dictionaries to keep track of how many times each client IP has queried each domain.

## Domain-IP Mapping:
- A dictionary (`DOMAIN_IP_MAP`) maps domain names to specific IP addresses. If a queried domain is not found in the dictionary, a default IP address (`192.168.1.100`) is returned.

## DNS Query Handling:
- The script defines two handler classes (`DNSUDPHandler` and `DNSTCPHandler`) to handle DNS queries over UDP and TCP, respectively.
- Each handler parses the DNS query, logs the query details, determines the appropriate IP address to return, and sends back a DNS response with an A record containing that IP address.

## Server Setup:
- In the main block, the script sets up UDP and TCP servers on port 53 (or a custom port if provided via command-line argument).
- It starts the servers and handles incoming DNS queries using separate threads for UDP and TCP.

## Graceful Shutdown:
- The script can be terminated using a keyboard interrupt, which will shut down the servers gracefully.

## Example of Usage:

To run the script, you would use a command like `python3 eyeDNSu` or `python3 eyeDNSu <custom_port>`.
The script will then start listening for DNS queries on the specified port and respond according to the domain-IP mappings defined in the `DOMAIN_IP_MAP` dictionary.

For more detailed information, you can view the file on GitHub.




Use Cases
The iDNS_CUP script is designed for various purposes, including:

    Testing and Development: Simulate a DNS server for testing applications that rely on DNS resolution and debug DNS-related issues in a controlled environment.
    DNS Spoofing or Redirection: Redirect DNS queries to specific IP addresses for testing how applications behave when DNS responses are manipulated or simulating malicious DNS spoofing attacks.
    Logging and Monitoring: Monitor DNS traffic and analyze query patterns by logging all DNS queries.
    Educational Purposes: Serve as a practical example of how DNS servers work and how to implement one using Python.

Functionality
DNS Query Handling
The script implements a fake DNS server that listens for DNS queries over both UDP and TCP. Key features include:

    Listening for DNS queries on port 53 (default DNS port) or a custom port specified via a command-line argument.
    Parsing incoming DNS queries using the dnslib library.
    Mapping the queried domain name to a predefined IP address using the DOMAIN_IP_MAP dictionary, with a default IP address (192.168.1.100) if the domain is not found.

Logging
The script logs details of each DNS query, including:

    Client IP address
    Queried domain name
    Response IP address
    Frequency of the query (how many times the same client has queried the same domain)
    Separate log files are maintained for UDP and TCP queries (dns_queries_udp.log and dns_queries_tcp.log).

UDP and TCP Support
The server handles DNS queries over both UDP and TCP protocols, with:

    TCP handling the DNS length prefix (the first two bytes) as required by the DNS-over-TCP protocol.

Query Frequency Tracking
The script tracks how often each client queries each domain using two dictionaries (udp_query_tracker and tcp_query_tracker).
Threading
The server runs two threads to spawn one UDP and one TCP daemon, simultaneously handling both protocols.
Getting Started
To use this script, run it with Python, specifying a custom port if desired. The script will start listening to DNS queries and logging them into the specified log files.
Technical Details
Protocol Layers

    UDP: Operates at the OSI model's Transport Layer (Layer 4).
    TCP: Also operates at Layer 4, but with additional reliability features.
    DNS: An Application Layer (Layer 7) protocol.
    The script leverages multi-threading (2 cores, 2 layers) to ensure compatibility with larger DNS responses.

Layer Breakdown

    Layer 4 (Transport Layer): UDP and TCP protocols.
    Layer 7 (Application Layer): DNS protocol.
    The script implements both DNSUDPHandler and DNSTCPHandler to handle DNS queries over UDP and TCP, respectively.
```
#### Change Log v1.2
```markdown
We’ve added an interactive menu when the server starts that asks the operator which action(s) should be performed on every DNS query:
	1.	Log
The server will log each query (to file and, optionally, to stdout in debug mode) and reply using the domain-to-IP mapping loaded from the config file.
	2.	Reroute
The server will not log queries. Instead, it will ignore the domain mapping and always return a fixed reroute IP address (in our example, "10.0.0.1").
	3.	Both
The server will do both – it logs the query and, at the same time, it overrides the configured IP with the reroute IP.

A global variable (ACTION_MODE) is set based on the menu choice. In the request handlers, the logic now checks this variable. For instance, when constructing the DNS response:
	•	If the mode is “log”:
It uses the normal lookup (resolve_ip(qname)) from the config file.
	•	If the mode is “reroute” or “both”:
It uses a predefined reroute IP (here, "10.0.0.1").
```
