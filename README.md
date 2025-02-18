iDNS_CUP
=====================================
Overview
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
