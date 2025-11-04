import socket
import threading
import time
import random
import re
import sys
import signal
from collections import defaultdict
from flask import Flask, render_template, jsonify

# --- Configuration ---
LISTEN_PORT = 8080
BUFFER_SIZE = 65536
MAX_CONNECTIONS = 200
REQUEST_TIMEOUT = 3.0
DASHBOARD_PORT = 5000

# --- Shared State for Dashboard & Proxy ---
stats = {
    "total_threats": 0,
    "blocked_requests": 0,
    "active_connections": 0,
    "attack_distribution": defaultdict(int),
}
intrusion_logs = []
domain_visits = defaultdict(int)
conn_lock = threading.Lock()

# --- Intrusion Detection System (IDS) ---
class SimpleIDS:
    def __init__(self):
        self.signatures = {
            "SQLi_UNION": re.compile(r"UNION\s+SELECT|SLEEP\(|WAITFOR\s+DELAY", re.IGNORECASE),
            "SQLi_OR_1": re.compile(r"(\'\s*OR\s*\'\d+\'=\'|\s+OR\s+1\s*=\s*1|--|\#)", re.IGNORECASE),
            "XSS_SCRIPT": re.compile(r"<\s*SCRIPT|alert\(|prompt\(|document\.cookie", re.IGNORECASE),
            "XSS_IMG_TAG": re.compile(r"<IMG\s+SRC=[\'\"]javascript:", re.IGNORECASE),
            "LFI_WIN_UNIX": re.compile(r"(\.\.\\){2,}|(\.\./){2,}|/etc/passwd|/etc/shadow", re.IGNORECASE),
            "CMD_INJECTION": re.compile(r"(\|\s*ls|;\s*cat|&&\s*id|&amp;&amp;\s*whoami)", re.IGNORECASE),
        }
        self.categories = {
            "SQLi_UNION": "SQL Injection", "SQLi_OR_1": "SQL Injection",
            "XSS_SCRIPT": "XSS", "XSS_IMG_TAG": "XSS",
            "LFI_WIN_UNIX": "LFI/Path Traversal", "CMD_INJECTION": "Command Injection"
        }

    def check_for_intrusion(self, data: bytes) -> tuple[bool, str, str]:
        try:
            data_str = data.decode('utf-8', 'ignore')
        except Exception:
            return False, "Binary data", None
        for name, pattern in self.signatures.items():
            if pattern.search(data_str):
                reason = f"Attack type: {name}"
                category = self.categories.get(name, "Other")
                return True, reason, category
        return False, "Clean", None

IDS_ENGINE = SimpleIDS()

def perform_intrusion_check(data: bytes, source: str) -> bool:
    is_malicious, reason, category = IDS_ENGINE.check_for_intrusion(data)
    if is_malicious:
        log_entry = {
            "id": len(intrusion_logs) + 1,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": random.choice(["Medium", "High", "Critical"]),
            "type": category or "Unknown",
            "source_ip": source.split(' ')[0], # Extract IP
            "status": "Blocked",
            "reason": reason
        }
        with conn_lock:
            intrusion_logs.append(log_entry)
            stats["total_threats"] += 1
            stats["blocked_requests"] += 1
            if category:
                stats["attack_distribution"][category] += 1
        print(f"🚨 [INTRUSION ALERT - {source}] {reason}")
        return True
    return False

# --- Proxy Server Logic ---
BLOCKED_DOMAINS = {"facebook.com", "youtube.com"}
FAKE_IPS = []  # No hardcoded IPs - configure as needed
FAKE_USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"]

def is_blocked(host):
    """
    Checks if a host or its parent domain is in the blocklist.
    This correctly handles subdomains like 'www.facebook.com'.
    """
    host_only = host.split(':')[0].lower()
    for domain in BLOCKED_DOMAINS:
        if host_only == domain or host_only.endswith('.' + domain):
            return True
    return False

def anonymize_request(request_data: str) -> str:
    lines = request_data.splitlines()
    if not lines: return request_data
    
    headers = {line.split(':', 1)[0].lower(): line.split(':', 1)[1].strip()
               for line in lines[1:] if ':' in line}

    if FAKE_IPS:
        fake_ip = random.choice(FAKE_IPS)
        headers['x-forwarded-for'] = fake_ip
        headers['x-real-ip'] = fake_ip
    headers['user-agent'] = random.choice(FAKE_USER_AGENTS)
    
    for h in ['via', 'x-proxy-id', 'forwarded']: headers.pop(h, None)
    
    new_headers = [f"{k.title()}: {v}" for k, v in headers.items()]
    return '\r\n'.join([lines[0]] + new_headers + ['', ''])

def tunnel_data(source, target):
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data: break
            target.sendall(data)
    except Exception:
        pass
    finally:
        source.close()
        target.close()

def handle_client(client_socket, addr):
    client_ip = addr[0]
    with conn_lock:
        stats["active_connections"] += 1
    
    try:
        request_data_raw = client_socket.recv(BUFFER_SIZE)
        if not request_data_raw: return

        if perform_intrusion_check(request_data_raw, f"{client_ip} initial request"):
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nIntrusion Detected.")
            return

        try:
            first_line = request_data_raw.split(b'\n')[0].decode()
            method, url, _ = first_line.split()
        except Exception:
            return

        host_header_match = re.search(rb"Host: ([^\r\n]+)", request_data_raw)
        if not host_header_match: return
        
        host_port = host_header_match.group(1).decode()
        if ':' in host_port:
            webserver, port_str = host_port.split(':')
            port = int(port_str)
        else:
            webserver, port = host_port, (443 if method == "CONNECT" else 80)

        domain_visits[webserver] += 1
        if is_blocked(webserver):
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked Domain.")
            return

        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect((webserver, port))

        if method == "CONNECT":
            client_socket.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            
            
            t1 = threading.Thread(target=tunnel_data, args=(client_socket, proxy_socket))
            t2 = threading.Thread(target=tunnel_data, args=(proxy_socket, client_socket))
            t1.daemon = True
            t2.daemon = True
            t1.start()
            t2.start()
            
            
            t1.join()
            t2.join()

        else: 
            anonymized_req = anonymize_request(request_data_raw.decode('latin-1')).encode('latin-1')
            proxy_socket.sendall(anonymized_req)
            tunnel_data(proxy_socket, client_socket)

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        with conn_lock:
            stats["active_connections"] -= 1
        client_socket.close()

def start_proxy_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(MAX_CONNECTIONS)
    print(f"🚀 Proxy server listening on port {LISTEN_PORT}")
    
    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

# --- Flask Dashboard Web Server ---
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def get_stats():
    with conn_lock:
        current_stats = stats.copy()
        current_stats["top_domains"] = sorted(domain_visits.items(), key=lambda x: x[1], reverse=True)[:5]
    return jsonify(current_stats)

@app.route("/api/alerts")
def get_alerts():
    with conn_lock:
        return jsonify(intrusion_logs[-15:])

if __name__ == "__main__":
    
    proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
    proxy_thread.start()
    
    
    print(f"📊 Dashboard available at http://127.0.0.1:{DASHBOARD_PORT}")
    app.run(port=DASHBOARD_PORT, debug=False)