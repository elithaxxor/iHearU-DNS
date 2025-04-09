#!/usr/bin/env python3
"""
fake_dns.py

This asynchronous fake DNS server supports both UDP and TCP.
It:
  - Loads dynamic domain-to-record mappings from a JSON config file and SQLite database.
  - Supports multiple DNS record types (A, AAAA, MX, TXT, CNAME, SRV) and includes a placeholder for DNSSEC validation.
  - Caches DNS responses with TTL.
  - Implements advanced security: rate limiting, IP blacklisting, and anomaly detection.
  - Logs query details to file, console (optional), and a database.
  - Provides real-time visualization via a Flask web server (with endpoints for pie chart, line graph, heat map, and raw data).
  - Is designed to be extended into real-time analytics dashboards using external frameworks.

Usage:
  python fake_dns.py [--debug] [--flask]
  python fake_dns.py visualize   # for CLI visualization menu
  python fake_dns.py test        # to run unit tests
"""

import asyncio
import sys
import logging
import json
import fnmatch
import time
import socket
import threading
import io
import sqlite3
from collections import defaultdict, Counter
from datetime import datetime
from functools import partial

# DNS functionality
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, MX, TXT, CNAME, SRV

# Visualization libraries
import matplotlib.pyplot as plt
import numpy as np

# Flask for online dashboard
from flask import Flask, Response, jsonify, render_template_string

# ================================
# CONFIGURATION & LOGGING SETUP
# ================================

LOG_FORMAT = "%(asctime)s - %(client_ip)s - %(query)s - %(response)s - %(frequency)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Set up loggers for UDP and TCP queries
udp_logger = logging.getLogger("udp_logger")
tcp_logger = logging.getLogger("tcp_logger")
udp_logger.setLevel(logging.INFO)
tcp_logger.setLevel(logging.INFO)

# File handlers for persistent logging
udp_file_handler = logging.FileHandler("dns_queries_udp.log")
tcp_file_handler = logging.FileHandler("dns_queries_tcp.log")
formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
udp_file_handler.setFormatter(formatter)
tcp_file_handler.setFormatter(formatter)
udp_logger.addHandler(udp_file_handler)
tcp_logger.addHandler(tcp_file_handler)

def add_stdout_logging():
    """Add console logging for debug mode."""
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    udp_logger.addHandler(stdout_handler)
    tcp_logger.addHandler(stdout_handler)

# Global action mode: "log", "reroute", or "both"
ACTION_MODE = "log"
REROUTE_IP = "10.0.0.1"
DEFAULT_TTL = 60

def choose_action_mode():
    """Interactive menu to select DNS query handling mode."""
    global ACTION_MODE
    print("Select an action for DNS queries:")
    print("1. Log only")
    print("2. Reroute only")
    print("3. Both log and reroute")
    choice = input("Enter 1, 2, or 3: ").strip()
    if choice == "1":
        ACTION_MODE = "log"
    elif choice == "2":
        ACTION_MODE = "reroute"
    elif choice == "3":
        ACTION_MODE = "both"
    else:
        print("Invalid choice. Defaulting to 'log' mode.")
        ACTION_MODE = "log"
    print(f"Action mode set to: {ACTION_MODE}")

# ================================
# CONFIGURATION LOADER & DATABASE INTEGRATION
# ================================

CONFIG_PATH = "dns_config.json"

class DNSConfig:
    """Handles dynamic loading of DNS configuration from JSON and stores it in SQLite."""
    def __init__(self, config_path=CONFIG_PATH):
        self.config_path = config_path
        self.last_load_time = 0
        self.config = {}
        self.reload_interval = 60  # seconds

    def load(self):
        """Load configuration from JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
            self.last_load_time = time.time()
        except Exception as e:
            print(f"Failed to load config file '{self.config_path}': {e}")
            self.config = {}

    def get_mapping(self):
        """Reload configuration if needed."""
        if time.time() - self.last_load_time > self.reload_interval:
            self.load()
        return self.config

dns_config = DNSConfig()
dns_config.load()

# ================================
# DATABASE SETUP FOR LOGGING QUERIES
# ================================

DB_PATH = "dns_queries.db"

def init_db():
    """Initialize SQLite database for query logs."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            client_ip TEXT,
            domain TEXT,
            protocol TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_query_log(timestamp, client_ip, domain, protocol):
    """Insert a query log into the database asynchronously."""
    def db_task():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO query_logs (timestamp, client_ip, domain, protocol) VALUES (?, ?, ?, ?)",
                  (timestamp, client_ip, domain, protocol))
        conn.commit()
        conn.close()
    # Run in a separate thread so as not to block asyncio loop
    threading.Thread(target=db_task, daemon=True).start()

init_db()

# ================================
# RESPONSE CACHING (LRU with TTL)
# ================================

class DNSCache:
    """Cache DNS responses with TTL support."""
    def __init__(self):
        self.cache = {}  # (qname, qtype) -> (response bytes, expiry_time)

    def get(self, key):
        entry = self.cache.get(key)
        if entry and entry[1] > time.time():
            return entry[0]
        elif key in self.cache:
            del self.cache[key]
        return None

    def set(self, key, value, ttl=DEFAULT_TTL):
        expiry = time.time() + ttl
        self.cache[key] = (value, expiry)

dns_cache = DNSCache()

# ================================
# QUERY LOGGING, DATA COLLECTION & SECURITY
# ================================

udp_query_tracker = defaultdict(int)
tcp_query_tracker = defaultdict(int)
query_records = []  # List of (timestamp, domain, protocol)

# Rate limiting parameters: max requests per IP per time window (e.g., 10 reqs per 60 seconds)
RATE_LIMIT = 10
RATE_LIMIT_WINDOW = 60
request_counters = defaultdict(list)  # ip -> list of timestamps

# Simple IP blacklist
BLACKLIST = set(["192.0.2.1"])  # Example blacklisted IP; extend as needed

def check_rate_limit(client_ip):
    """Check and update rate limit for the given IP. Return True if allowed."""
    now = time.time()
    timestamps = request_counters[client_ip]
    # Remove timestamps older than window
    request_counters[client_ip] = [ts for ts in timestamps if now - ts < RATE_LIMIT_WINDOW]
    if len(request_counters[client_ip]) >= RATE_LIMIT:
        return False
    request_counters[client_ip].append(now)
    return True

def anomaly_detection(client_ip):
    """Simple anomaly detection: log a warning if an IP exceeds threshold (e.g., 20 reqs)."""
    if len(request_counters[client_ip]) > 20:
        udp_logger.warning(f"Anomaly detected: High request rate from {client_ip}")

def log_query(logger, query_tracker, client_ip, query, response):
    """Log query details, update counters, store record for visualization, and write to DB."""
    query_tracker[(client_ip, query)] += 1
    log_data = {
        "client_ip": client_ip,
        "query": query,
        "response": response,
        "frequency": query_tracker[(client_ip, query)]
    }
    logger.info("Query received", extra=log_data)
    record = (time.time(), query, logger.name.split('_')[0].upper())
    query_records.append(record)
    insert_query_log(*record)

# ================================
# DNS RECORD SUPPORT & DNSSEC PLACEHOLDER
# ================================

def dnssec_validate(request):
    """Placeholder for DNSSEC validation. Return True if valid."""
    # Real implementation would verify signatures and key records.
    return True

def resolve_ip(qname, qtype):
    """
    Resolve the record value based on configuration with wildcard support.
    Returns (record_value, ttl) or (None, ttl) if not found.
    """
    mapping = dns_config.get_mapping()
    if qname in mapping:
        rec = mapping[qname]
        if isinstance(rec, dict):
            return rec.get(qtype, None), rec.get("ttl", DEFAULT_TTL)
        else:
            return rec, DEFAULT_TTL
    for pattern, rec in mapping.items():
        if '*' in pattern and fnmatch.fnmatch(qname, pattern):
            if isinstance(rec, dict):
                return rec.get(qtype, None), rec.get("ttl", DEFAULT_TTL)
            else:
                return rec, DEFAULT_TTL
    if qtype == "A":
        return "192.168.1.100", DEFAULT_TTL
    return None, DEFAULT_TTL

def build_dns_response(request):
    """
    Build a DNS response based on the query.
    Supports A, AAAA, MX, TXT, CNAME, and SRV.
    Uses caching and optionally DNSSEC validation.
    """
    if len(request.pack()) > 512:
        return None

    qname = str(request.q.qname)
    qtype_str = QTYPE[request.q.qtype]
    supported_types = {"A", "AAAA", "MX", "TXT", "CNAME", "SRV"}
    if qtype_str not in supported_types:
        return DNSRecord(header=request.header, q=request.q)

    cache_key = (qname, qtype_str)
    cached_response = dns_cache.get(cache_key)
    if cached_response:
        return DNSRecord.parse(cached_response)

    # Action mode handling
    if ACTION_MODE in ("reroute", "both"):
        record_value = REROUTE_IP
        ttl = DEFAULT_TTL
    else:
        record_value, ttl = resolve_ip(qname, qtype_str)
        if record_value is None:
            return DNSRecord(header=request.header, q=request.q)

    reply = DNSRecord(header=request.header, q=request.q)

    if qtype_str == "A":
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(record_value), ttl=ttl))
    elif qtype_str == "AAAA":
        reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(record_value), ttl=ttl))
    elif qtype_str == "MX":
        reply.add_answer(RR(qname, QTYPE.MX, rdata=MX(record_value), ttl=ttl))
    elif qtype_str == "TXT":
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(record_value), ttl=ttl))
    elif qtype_str == "CNAME":
        reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(record_value), ttl=ttl))
    elif qtype_str == "SRV":
        # For SRV, record_value should be in the format "priority weight port target"
        parts = record_value.split()
        if len(parts) == 4:
            priority, weight, port, target = parts
            reply.add_answer(RR(qname, QTYPE.SRV, rdata=SRV(int(priority), int(weight), int(port), target), ttl=ttl))
    # Optionally perform DNSSEC validation (placeholder)
    if not dnssec_validate(request):
        # In a real scenario, set error flags in the header
        pass

    dns_cache.set(cache_key, reply.pack(), ttl)
    return reply

async def process_dns_query(data, client_ip, protocol):
    """
    Process a raw DNS query and return a response.
    Performs rate limiting, blacklisting, logging, and validation.
    """
    # Check IP blacklist
    if client_ip in BLACKLIST:
        if protocol == "UDP":
            udp_logger.warning(f"Blacklisted IP {client_ip} attempted query")
        else:
            tcp_logger.warning(f"Blacklisted IP {client_ip} attempted query")
        return None

    # Rate limiting check
    if not check_rate_limit(client_ip):
        if protocol == "UDP":
            udp_logger.warning(f"Rate limit exceeded for {client_ip}")
        else:
            tcp_logger.warning(f"Rate limit exceeded for {client_ip}")
        return None

    anomaly_detection(client_ip)

    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        if protocol == "UDP":
            udp_logger.error(f"Failed to parse DNS request from {client_ip}: {e}")
        else:
            tcp_logger.error(f"Failed to parse DNS request from {client_ip} over TCP: {e}")
        return None

    qname = str(request.q.qname)
    qtype_str = QTYPE[request.q.qtype]
    supported_types = {"A", "AAAA", "MX", "TXT", "CNAME", "SRV"}
    if qtype_str not in supported_types:
        print(f"Unsupported query type {qtype_str} from {client_ip} for {qname}")
        return None

    if ACTION_MODE in ("log", "both"):
        if protocol == "UDP":
            log_query(udp_logger, udp_query_tracker, client_ip, qname, "response prepared")
        else:
            log_query(tcp_logger, tcp_query_tracker, client_ip, qname, "response prepared")

    reply = build_dns_response(request)
    return reply

# ================================
# ASYNCHRONOUS UDP & TCP SERVERS
# ================================

class DNSUDPProtocol(asyncio.DatagramProtocol):
    """Asyncio protocol to handle UDP DNS requests."""
    def datagram_received(self, data, addr):
        client_ip, _ = addr
        asyncio.create_task(self.handle_request(data, addr))

    async def handle_request(self, data, addr):
        client_ip, _ = addr
        reply = await process_dns_query(data, client_ip, "UDP")
        if reply:
            self.transport.sendto(reply.pack(), addr)

async def handle_tcp_client(reader, writer):
    """Asynchronous TCP client handler for DNS queries."""
    client_ip = writer.get_extra_info('peername')[0]
    try:
        length_bytes = await reader.readexactly(2)
        length = int.from_bytes(length_bytes, 'big')
        data = await reader.readexactly(length)
    except Exception as e:
        tcp_logger.error(f"Error reading TCP data from {client_ip}: {e}")
        writer.close()
        await writer.wait_closed()
        return

    reply = await process_dns_query(data, client_ip, "TCP")
    if reply:
        response_data = reply.pack()
        writer.write(len(response_data).to_bytes(2, 'big') + response_data)
        await writer.drain()
    writer.close()
    await writer.wait_closed()

async def start_servers(port):
    """Start UDP and TCP DNS servers using asyncio."""
    loop = asyncio.get_running_loop()
    print(f"Starting UDP DNS server on port {port}")
    udp_transport, _ = await loop.create_datagram_endpoint(DNSUDPProtocol, local_addr=("", port))
    print(f"Starting TCP DNS server on port {port}")
    tcp_server = await asyncio.start_server(handle_tcp_client, host="", port=port)
    async with tcp_server:
        await tcp_server.serve_forever()

# ================================
# VISUALIZATION FUNCTIONS & REAL-TIME ANALYTICS API
# ================================

def generate_pie_chart():
    """Generate a pie chart of DNS query distribution by domain and return image bytes."""
    domains = [record[1] for record in query_records]
    counter = Counter(domains)
    labels = list(counter.keys())
    sizes = list(counter.values())
    plt.figure()
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
    plt.title("DNS Query Distribution by Domain")
    plt.axis("equal")
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)
    return buf

def generate_line_graph():
    """Generate a line graph of DNS query trends over time and return image bytes."""
    times = [datetime.fromtimestamp(record[0]).strftime("%H:%M") for record in query_records]
    counter = Counter(times)
    sorted_times = sorted(counter.keys())
    counts = [counter[tm] for tm in sorted_times]
    plt.figure()
    plt.plot(sorted_times, counts, marker='o')
    plt.xticks(rotation=45)
    plt.title("DNS Query Trends Over Time (per minute)")
    plt.xlabel("Time (HH:MM)")
    plt.ylabel("Query Count")
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)
    return buf

def generate_heat_map():
    """Generate a heat map of DNS query counts per hour and return image bytes."""
    hours = [datetime.fromtimestamp(record[0]).hour for record in query_records]
    counter = Counter(hours)
    heat = np.zeros(24)
    for hr in range(24):
        heat[hr] = counter.get(hr, 0)
    plt.figure()
    plt.imshow(heat.reshape(1, -1), cmap="hot", aspect="auto")
    plt.colorbar(label="Query Count")
    plt.yticks([]) 
    plt.xticks(np.arange(24), np.arange(24))
    plt.title("DNS Query Heat Map (by Hour of Day)")
    plt.xlabel("Hour of Day")
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)
    return buf

# Flask application for online real-time analytics dashboard
flask_app = Flask(__name__)

@flask_app.route("/")
def index():
    html = """
    <h1>DNS Query Visualization Dashboard</h1>
    <ul>
      <li><a href='/pie'>Pie Chart</a></li>
      <li><a href='/line'>Line Graph</a></li>
      <li><a href='/heat'>Heat Map</a></li>
      <li><a href='/data'>Raw Query Data (JSON)</a></li>
    </ul>
    """
    return render_template_string(html)

@flask_app.route("/pie")
def pie_chart():
    buf = generate_pie_chart()
    return Response(buf.getvalue(), mimetype="image/png")

@flask_app.route("/line")
def line_graph():
    buf = generate_line_graph()
    return Response(buf.getvalue(), mimetype="image/png")

@flask_app.route("/heat")
def heat_map():
    buf = generate_heat_map()
    return Response(buf.getvalue(), mimetype="image/png")

@flask_app.route("/data")
def raw_data():
    """Return collected query data in JSON format."""
    data = [{"timestamp": ts, "domain": domain, "protocol": protocol} for (ts, domain, protocol) in query_records]
    return jsonify(data)

def start_flask_server(port=5000):
    """Start Flask server in a separate thread."""
    def run_app():
        flask_app.run(host="0.0.0.0", port=port)
    thread = threading.Thread(target=run_app, daemon=True)
    thread.start()

# ================================
# UNIT TESTS (BASIC INTEGRATION)
# ================================

import unittest

class TestFakeDNSServer(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        global ACTION_MODE
        ACTION_MODE = "log"
        cls.port = 5353
        cls.loop = asyncio.get_event_loop()
        cls.udp_transport, _ = cls.loop.run_until_complete(
            asyncio.get_running_loop().create_datagram_endpoint(DNSUDPProtocol, local_addr=("", cls.port))
        )
        cls.tcp_server = cls.loop.run_until_complete(asyncio.start_server(handle_tcp_client, host="", port=cls.port))
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.udp_transport.close()
        cls.tcp_server.close()

    async def test_udp_dns_query(self):
        qname = "example.com."
        request = DNSRecord.question(qname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(request.pack(), ("127.0.0.1", self.port))
        data, _ = sock.recvfrom(1024)
        response = DNSRecord.parse(data)
        self.assertEqual(str(response.q.qname), qname)
        sock.close()

    async def test_tcp_dns_query(self):
        qname = "test.com."
        request = DNSRecord.question(qname)
        data = request.pack()
        prefixed_data = len(data).to_bytes(2, "big") + data
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(prefixed_data)
        await writer.drain()
        len_bytes = await reader.readexactly(2)
        resp_len = int.from_bytes(len_bytes, 'big')
        resp_data = await reader.readexactly(resp_len)
        response = DNSRecord.parse(resp_data)
        self.assertEqual(str(response.q.qname), qname)
        writer.close()
        await writer.wait_closed()

# ================================
# MAIN ENTRY POINT
# ================================

if __name__ == "__main__":
    # Option to run Flask server for online dashboard
    if "--flask" in sys.argv:
        start_flask_server(5000)
        print("Flask web server started on port 5000 for visualization.")

    if "--debug" in sys.argv:
        add_stdout_logging()
    if "test" in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    elif "visualize" in sys.argv:
        # CLI visualization menu
        print("Launching CLI visualization menu...")
        print("1. Pie Chart\n2. Line Graph\n3. Heat Map\n4. All")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            buf = generate_pie_chart()
            plt.imshow(plt.imread(buf))
            plt.show()
        elif choice == "2":
            buf = generate_line_graph()
            plt.imshow(plt.imread(buf))
            plt.show()
        elif choice == "3":
            buf = generate_heat_map()
            plt.imshow(plt.imread(buf))
            plt.show()
        elif choice == "4":
            buf = generate_pie_chart()
            plt.imshow(plt.imread(buf))
            plt.show()
            buf = generate_line_graph()
            plt.imshow(plt.imread(buf))
            plt.show()
            buf = generate_heat_map()
            plt.imshow(plt.imread(buf))
            plt.show()
    else:
        choose_action_mode()
        port = 53
        for arg in sys.argv[1:]:
            if arg.isdigit():
                port = int(arg)
        print(f"Starting fake DNS server on UDP and TCP port {port} (asyncio)")
        try:
            asyncio.run(start_servers(port))
        except KeyboardInterrupt:
            print("Shutting down fake DNS server.")
