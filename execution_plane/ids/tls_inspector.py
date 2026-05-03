import re
import sys
import os
from mitmproxy import http

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from communication.client import send_log
except ImportError:
    def send_log(*args, **kwargs):
        pass

LOG_DIR = "logs"
LOG_FILE = "logs/tls_events.csv"

def init_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        import csv
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "event_type", "attack_type", "src_ip", "detail", "confidence"])

def log_event(event: str, attack: str, src: str, detail: str = "", confidence: str = ""):
    import csv, time
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([time.time(), event, attack, src, detail, confidence])

init_logger()

PATTERNS = {
    "SQL_INJECTION": re.compile(rb"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|xp_cmdshell|information_schema)"),
    "XSS": re.compile(rb"(?i)(<script[^>]*>|on(load|click|mouseover|error|focus)\s*=|javascript:[^\s])"),
    "PATH_TRAVERSAL": re.compile(rb"(\.\./|\.\.\\|%2e%2e%2f)|((?i)/etc/passwd|/etc/shadow|/windows/system32)"),
    "SSRF": re.compile(rb"(?i)(url|uri|dest|redirect|next|src)=[^&\s]*(127\.0\.0\.1|localhost|169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
}

def request(flow: http.HTTPFlow) -> None:
    src_ip = flow.client_conn.peername[0]
    
    content = flow.request.content
    query = flow.request.query
    
    for name, pat in PATTERNS.items():
        if content and pat.search(content):
            send_alert(name, src_ip, f"Payload match in body: {pat.pattern}")
            return
            
        for k, v in query.items():
            if v and pat.search(v.encode()):
                send_alert(name, src_ip, f"Payload match in query: {k}={v}")
                return

def send_alert(attack_type: str, src_ip: str, detail: str):
    print(f"[TLS INSPECTOR] {attack_type} detected from {src_ip}")
    log_event("TLS_ATTACK", attack_type, src_ip, detail, "HIGH")
    try:
        send_log(attack_type, src_ip, confidence="HIGH", detail=detail)
    except Exception as e:
        print(f"[TLS INSPECTOR ERROR] Failed to send log: {e}")
