"""
MACDS Deep Packet Inspector — Peak Version

Upgrades vs previous version:
  - INTERFACE read from MACDS_INTERFACE env var (was hardcoded s1-eth3)
  - Flow tracker: measures connection_count, flow_duration, unique_ports,
    syn_ack_ratio, payload_entropy per source IP and sends to control plane
  - Brute force detection: SSH (port 22), RDP (port 3389), FTP (port 21)
    via completed short-flow counting in 10-second windows
  - Data exfiltration: internal→external large volume + high entropy
  - 6 new payload patterns: Spring4Shell, Heartbleed, Struts RCE,
    PHP injection, XXE, SSTI
  - 443 removed from HTTP inspect (encrypted, unreadable)
  - Port scan classification uses flow.unique_ports not string matching
"""

import os
import sys
import re
import csv
import math
import time
import threading
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, IPSession, IPv6

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from communication.client import send_log, start_polling
except ImportError:
    print("[ERROR] Cannot import communication.client. Run from project root.")
    sys.exit(1)

INTERFACE    = os.environ.get("MACDS_INTERFACE", "eth0")

# IPs to never flag — server's own addresses + trusted infra
# Set MACDS_WHITELIST as comma-separated IPs in environment
_WHITELIST_RAW = os.environ.get("MACDS_WHITELIST", "")
WHITELIST_IPS  = set(
    ip.strip() for ip in _WHITELIST_RAW.split(",") if ip.strip()
)
LOG_DIR      = "logs"
LOG_FILE     = "logs/dpi_events.csv"
OFFLINE_MODE = False


def init_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow([
                "timestamp", "event_type", "attack_type",
                "src_ip", "detail", "confidence"
            ])

def log_event(event: str, attack: str, src: str,
              detail: str = "", confidence: str = ""):
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([
            time.time(), event, attack, src, detail, confidence
        ])

def send_alert(attack_type: str, src_ip: str,
               packet_rate: float = 0.0,
               confidence: str = "MEDIUM",
               detail: str = "",
               extra_state: dict = None):
    if OFFLINE_MODE:
        return
    kwargs = {
        "packet_rate": packet_rate,
        "confidence":  confidence,
        "detail":      detail,
    }
    if extra_state:
        kwargs.update(extra_state)
    send_log(attack_type, src_ip, **kwargs)


def get_ip_layer(pkt):
    if IP   in pkt: return pkt[IP]
    if IPv6 in pkt: return pkt[IPv6]
    return None

def get_src_ip(pkt):
    ip = get_ip_layer(pkt)
    return ip.src if ip else None

def get_dst_ip(pkt):
    ip = get_ip_layer(pkt)
    return ip.dst if ip else None


def payload_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = defaultdict(int)
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_suspicion_scores = defaultdict(lambda: {"score": 0.0, "last_update": 0.0})
_suspicion_lock   = threading.Lock()
SUSPICION_DECAY              = 0.95
SUSPICION_ESCALATE_THRESHOLD = 15.0

def update_suspicion(ip: str, delta: float) -> float:
    now = time.time()
    with _suspicion_lock:
        e = _suspicion_scores[ip]
        if e["last_update"] == 0:
            e["score"] = delta
            e["last_update"] = now
            return e["score"]
        elapsed = now - e["last_update"]
        e["score"] *= SUSPICION_DECAY ** elapsed
        e["score"] += delta
        e["last_update"] = now
        return e["score"]

def get_suspicion(ip: str) -> float:
    now = time.time()
    with _suspicion_lock:
        e = _suspicion_scores[ip]
        if e["last_update"] > 0:
            return e["score"] * SUSPICION_DECAY ** (now - e["last_update"])
        return 0.0


_tcp_streams      = defaultdict(bytearray)
_stream_last_seen = defaultdict(float)
_stream_lock      = threading.Lock()
MAX_STREAM_BUFFER = 8192
STREAM_IDLE_TIMEOUT = 120

def get_reassembled_payload(pkt) -> bytes:
    if TCP not in pkt or Raw not in pkt: return b""
    src_ip = get_src_ip(pkt); dst_ip = get_dst_ip(pkt)
    if not src_ip or not dst_ip: return b""
    key = (src_ip, dst_ip, pkt[TCP].sport, pkt[TCP].dport)
    with _stream_lock:
        _stream_last_seen[key] = time.time()
        _tcp_streams[key] += bytes(pkt[Raw].load)
        if len(_tcp_streams[key]) > MAX_STREAM_BUFFER:
            _tcp_streams[key] = _tcp_streams[key][-MAX_STREAM_BUFFER:]
        if pkt[TCP].flags & 0x01 or pkt[TCP].flags & 0x04:
            data = bytes(_tcp_streams[key])
            del _tcp_streams[key]
            _stream_last_seen.pop(key, None)
            return data
        return bytes(_tcp_streams[key])


_flows      = defaultdict(lambda: {
    "active":       {},
    "syn_count":    0,
    "ack_count":    0,
    "durations":    deque(maxlen=100),
    "unique_ports": set(),
    "bytes_out":    0,
    "last_seen":    0.0,
})
_flows_lock = threading.Lock()

def update_flow(pkt):
    now = time.time()
    src = get_src_ip(pkt)
    if not src: return
    with _flows_lock:
        f = _flows[src]; f["last_seen"] = now
        if TCP in pkt:
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport
            dst   = get_dst_ip(pkt)
            key   = (dst, dport)
            f["unique_ports"].add(dport)
            if (flags & 0x02) and not (flags & 0x10):
                f["syn_count"] += 1; f["active"][key] = now
            if flags & 0x10:
                f["ack_count"] += 1
            if (flags & 0x01) or (flags & 0x04):
                if key in f["active"]:
                    f["durations"].append(now - f["active"].pop(key))
        if Raw in pkt:
            f["bytes_out"] += len(pkt[Raw].load)

def get_flow_state(ip: str) -> dict:
    with _flows_lock:
        f = _flows.get(ip)
        if not f:
            return {"connection_count": 0, "flow_duration": 0.0,
                    "unique_ports": 0, "syn_ack_ratio": 1.0, "bytes_out": 0}
        avg = sum(f["durations"]) / len(f["durations"]) if f["durations"] else 0.0
        ratio = f["ack_count"] / max(f["syn_count"], 1)
        return {
            "connection_count": len(f["active"]),
            "flow_duration":    avg,
            "unique_ports":     len(f["unique_ports"]),
            "syn_ack_ratio":    min(ratio, 1.0),
            "bytes_out":        f["bytes_out"],
        }


ip_profiles = defaultdict(lambda: {
    "syn_ts":      deque(maxlen=200),
    "ack_ts":      deque(maxlen=200),
    "ports":       set(),
    "timing_gaps": deque(maxlen=100),
    "last_ts":     None,
    "last_seen":   0.0,
})
profiles_lock = threading.Lock()

def update_profile(pkt):
    now = time.time()
    src = get_src_ip(pkt)
    if not src: return
    with profiles_lock:
        p = ip_profiles[src]; p["last_seen"] = now
        if p["last_ts"] is not None:
            p["timing_gaps"].append(now - p["last_ts"])
        p["last_ts"] = now
        if TCP in pkt:
            flags = pkt[TCP].flags
            if (flags & 0x02) and not (flags & 0x10):
                p["syn_ts"].append(now)
            if flags & 0x10:
                p["ack_ts"].append(now)
            p["ports"].add(pkt[TCP].dport)

def analyze_behavior(src_ip):
    with profiles_lock:
        if src_ip not in ip_profiles:
            return {"suspicious": False, "score": 0, "reasons": []}
        p    = ip_profiles[src_ip]
        syns = list(p["syn_ts"])
        acks = list(p["ack_ts"])
        ports = set(p["ports"])
        gaps = list(p["timing_gaps"])
    score, reasons = 0, []; now = time.time()
    if len(syns) > 5:
        ratio = len(acks) / max(len(syns), 1)
        if ratio < 0.1:
            score += 3
            reasons.append(
                f"SYN/ACK ratio={ratio:.2f} — {len(syns)} SYNs, only {len(acks)} ACKs"
            )
    if len(ports) > 10:
        score += 2
        reasons.append(f"Hit {len(ports)} unique destination ports")
    if len(gaps) > 20:
        mean   = sum(gaps) / len(gaps)
        stddev = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5
        cv     = stddev / (mean + 1e-9)
        if cv < 0.05 and mean < 0.01:
            score += 3
            reasons.append(
                f"Machine-regular timing CV={cv:.4f} mean={mean*1000:.2f}ms"
            )
    recent = sum(1 for ts in syns if now - ts <= 2.0)
    if recent > 30:
        score += 2; reasons.append(f"{recent} SYNs in last 2s")
    return {"suspicious": score >= 3, "score": score, "reasons": reasons}


def tcp_fingerprint(pkt) -> dict:
    ip_layer = get_ip_layer(pkt)
    if not ip_layer: return {"suspicious": False}
    ttl = ip_layer.ttl if IP in pkt else pkt[IPv6].hlim
    win = pkt[TCP].window
    src = get_src_ip(pkt)
    beh = analyze_behavior(src)
    if beh["score"] >= 3:
        return {"suspicious": True, "match": "BEHAVIORAL",
                "reason": "; ".join(beh["reasons"])}
    if IP in pkt and pkt[IP].id == 0 and (pkt[IP].flags & 0x2):
        return {"match": "SPOOFED", "suspicious": True,
                "reason": "IP ID=0 with DF bit — packet forging tool"}
    if win in (512, 1024):
        return {"match": "TOOL", "suspicious": True,
                "reason": f"Window={win} — hping3/nmap default"}
    if ttl == 255:
        return {"match": "RAW_SOCKET", "suspicious": True,
                "reason": "TTL=255 — raw socket"}
    opts = set()
    for opt in pkt[TCP].options:
        n = opt[0]
        if n in (2, "MSS"):       opts.add("MSS")
        elif n in (4, "SAckOK"):  opts.add("SACK")
        elif n in (8, "Timestamp"): opts.add("TS")
        elif n in (3, "WScale"):  opts.add("WS")
    req = {"MSS", "SACK", "TS", "WS"}
    if 60 <= ttl <= 65  and 28000 <= win <= 30000:
        ok = req.issubset(opts)
        return {"match": "Linux",   "suspicious": not ok,
                "reason": "Looks like Linux"   if ok else f"Linux missing {req-opts}"}
    if 120 <= ttl <= 130 and 64000 <= win <= 66000:
        ok = req.issubset(opts)
        return {"match": "Windows", "suspicious": not ok,
                "reason": "Looks like Windows" if ok else f"Windows missing {req-opts}"}
    if 62 <= ttl <= 65  and 65000 <= win <= 66000:
        ok = req.issubset(opts)
        return {"match": "macOS",   "suspicious": not ok,
                "reason": "Looks like macOS"   if ok else f"macOS missing {req-opts}"}
    if 62 <= ttl <= 65  and 14000 <= win <= 15000:
        ok = req.issubset(opts)
        return {"match": "Android", "suspicious": not ok,
                "reason": "Looks like Android" if ok else f"Android missing {req-opts}"}
    return {"match": "UNKNOWN", "suspicious": True,
            "reason": f"Unknown fingerprint TTL={ttl} WIN={win} opts={opts}"}


BRUTE_PORTS     = {22: "SSH_BRUTE_FORCE", 3389: "RDP_BRUTE_FORCE", 21: "FTP_BRUTE_FORCE"}
BRUTE_THRESHOLD = 5
_brute          = defaultdict(lambda: defaultdict(deque))
_brute_lock     = threading.Lock()

def check_brute_force(pkt):
    if TCP not in pkt: return None
    dport = pkt[TCP].dport
    if dport not in BRUTE_PORTS: return None
    flags = pkt[TCP].flags
    if not ((flags & 0x01) or (flags & 0x04)): return None
    src = get_src_ip(pkt); now = time.time()
    with _brute_lock:
        q = _brute[src][dport]; q.append(now)
        while q and now - q[0] > 10.0: q.popleft()
        count = len(q)
    if count >= BRUTE_THRESHOLD:
        return {"attack_type": BRUTE_PORTS[dport], "confidence": "HIGH",
                "detail": f"{count} auth attempts to port {dport} in 10s"}
    return None


EXFIL_BYTES_THRESHOLD = 5_000_000
EXFIL_WINDOW_SECONDS  = 60
_exfil                = defaultdict(lambda: {"bytes": 0, "start": 0.0,
                                              "destinations": set()})
_exfil_lock           = threading.Lock()

def check_exfiltration(pkt):
    if Raw not in pkt: return None
    src = get_src_ip(pkt); dst = get_dst_ip(pkt)
    if not src or not dst: return None
    try:
        import ipaddress as _ip
        if not _ip.ip_address(src).is_private: return None
        if _ip.ip_address(dst).is_private:     return None
    except Exception: return None
    now  = time.time()
    size = len(pkt[Raw].load)
    entr = payload_entropy(pkt[Raw].load)
    with _exfil_lock:
        e = _exfil[src]
        if e["start"] == 0.0 or now - e["start"] > EXFIL_WINDOW_SECONDS:
            e["bytes"] = 0; e["start"] = now; e["destinations"] = set()
        e["bytes"] += size; e["destinations"].add(dst)
        if e["bytes"] >= EXFIL_BYTES_THRESHOLD and entr > 6.0:
            mb = e["bytes"] / 1_000_000
            return {"attack_type": "DATA_EXFILTRATION", "confidence": "HIGH",
                    "detail": f"{mb:.1f}MB to {len(e['destinations'])} IPs entropy={entr:.1f}"}
    return None


def inspect_http(pkt):
    payload = bytes(pkt[Raw].load)
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ",
               b"HEAD ", b"OPTIONS ", b"PATCH ")
    if not payload.startswith(methods):
        return {"is_http": False, "is_real_browser": True, "reason": ""}
    lines = payload.split(b"\r\n")
    if not lines:
        return {"is_http": False, "is_real_browser": True, "reason": ""}
    if b"HTTP/1.0" in lines[0]:
        return {"is_http": True, "is_real_browser": False,
                "reason": "HTTP/1.0 — bot/tool"}
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    if b"user-agent" not in headers:
        return {"is_http": True, "is_real_browser": False,
                "reason": "Missing User-Agent"}
    ua    = headers[b"user-agent"]
    known = (b"Mozilla/5.0", b"Chrome/", b"Firefox/", b"Safari/",
             b"Edge/", b"curl/", b"python-requests")
    if not any(v in ua for v in known):
        return {"is_http": True, "is_real_browser": False,
                "reason": f"Unknown UA: {ua[:60]}"}
    signals = sum(
        1 for k in headers
        if k.startswith(b"sec-fetch-") or k in (b"accept-language", b"accept-encoding")
    )
    if signals < 2:
        return {"is_http": True, "is_real_browser": False,
                "reason": "Missing browser headers"}
    return {"is_http": True, "is_real_browser": True, "reason": "Real browser"}


def inspect_dns(pkt):
    if pkt[DNS].qr != 0:
        return {"suspicious": False, "attack_type": None, "reason": ""}
    if getattr(pkt[DNS], "qdcount", 0) == 0 or not pkt[DNS].qd:
        return {"suspicious": False, "attack_type": None, "reason": ""}
    qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
    qtype = pkt[DNS].qd.qtype
    if qtype == 255:
        return {"suspicious": True, "attack_type": "DNS_AMPLIFICATION",
                "reason": f"ANY query for {qname} — amplification"}
    if qtype == 12:
        return {"suspicious": True, "attack_type": "DNS_SCAN",
                "reason": "PTR query — reverse DNS scanning"}
    label = qname.split(".")[0] if qname else ""
    if len(label) > 10:
        n    = len(label)
        freq = {c: label.count(c) for c in set(label)}
        entr = -sum((freq[c] / n) * math.log2(freq[c] / n) for c in freq)
        if entr > 3.8:
            return {"suspicious": True, "attack_type": "DNS_DGA",
                    "reason": f"High-entropy domain (entropy={entr:.2f}) — DGA"}
    return {"suspicious": False, "attack_type": None, "reason": ""}


PATTERNS = {
    "SQL_INJECTION": re.compile(
        rb"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|xp_cmdshell"
        rb"|information_schema|benchmark\s*\(|sleep\s*\(\d+\)|pg_sleep"
        rb"|waitfor\s+delay)"
    ),
    "XSS": re.compile(
        rb"(?i)(<script[^>]*>|on(load|click|mouseover|error|focus|keyup"
        rb"|keydown|submit|blur)\s*=|javascript:[^\s]|<iframe[^>]*>"
        rb"|document\.(cookie|write)|eval\s*\()"
    ),
    "PATH_TRAVERSAL": re.compile(
        rb"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)"
        rb"|(/etc/(passwd|shadow|hosts)|/windows/system32"
        rb"|/proc/self/environ)"
    ),
    "LOG4SHELL": re.compile(
        rb"(?i)\$\{jndi\s*:(ldap|rmi|dns|iiop|corba|nis|nds)s?://"
    ),
    "SHELLSHOCK": re.compile(rb"\(\s*\)\s*\{[^}]*\}\s*;"),
    "CMD_INJECTION": re.compile(
        rb"(?i)(?<![a-z0-9_])(;|\||&&|\$\(|`)\s*"
        rb"(ls|cat|id|whoami|wget|curl|bash|sh|nc|ncat|netcat|python|perl|ruby)\b"
    ),
    "SSRF": re.compile(
        rb"(?i)(url|uri|dest|redirect|next|src|path|load|fetch|open|file)"
        rb"=[^&\s]*(127\.0\.0\.1|localhost|169\.254\.|10\.\d+\.\d+\.\d+"
        rb"|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1)"
    ),
    "SPRING4SHELL": re.compile(
        rb"(?i)(class\.module\.classLoader|ClassLoader\.resources"
        rb"|spring\.expression)"
    ),
    "HEARTBLEED": re.compile(rb"\x18\x03[\x00-\x03].{0,3}\x01"),
    "STRUTS_RCE": re.compile(
        rb"(?i)(ognl\.|%\{|#[a-z]+\(|redirectAction:|action:)"
        rb".{0,100}(exec|runtime|process|getRuntime)"
    ),
    "PHP_INJECTION": re.compile(
        rb"(?i)(php://input|php://filter|php://fd"
        rb"|expect://|data://text/plain;base64)"
    ),
    "XXE": re.compile(
        rb"(?i)(<!ENTITY\s+\w+\s+SYSTEM|<!DOCTYPE[^>]*\[)"
    ),
    "SSTI": re.compile(
        rb"(?i)(\{\{[^}]*(config|self|class|mro|import|exec|eval"
        rb"|request|application|global)[^}]*\}\}"
        rb"|\{%[^%]*(import|exec|eval|from|include)[^%]*%\}"
        rb"|\${[^}]*(class|exec|eval|import|runtime)[^}]*}"
        rb"|#\{[^}]*(class|exec|eval|import)[^}]*\}"
        rb"|<%=[^%]*(exec|eval|system|runtime)[^%]*%>)"
    ),
}

def scan_payload(pkt):
    return scan_payload_bytes(bytes(pkt[Raw].load), get_src_ip(pkt))

def scan_payload_bytes(data: bytes, src_ip: str):
    if len(data) < 4:
        return {"hit": False, "attack_type": None, "match": None}
    for name, pat in PATTERNS.items():
        m = pat.search(data)
        if m:
            return {"hit": True, "attack_type": name,
                    "match": m.group(0)[:80].decode(errors="replace")}
    return {"hit": False, "attack_type": None, "match": None}


def make_verdict(src, pkt, fp, http, dns, payload, behavior,
                 brute=None, exfil=None, flow=None):
    if flow is None: flow = {}
    src_ip = get_src_ip(pkt); dst_ip = get_dst_ip(pkt)
    if src_ip and src_ip == dst_ip:
        return {"verdict": "ATTACK", "attack_type": "LAND_ATTACK",
                "confidence": "HIGH", "reasons": ["src==dst"], "flow": flow}
    if payload.get("hit"):
        return {"verdict": "ATTACK", "attack_type": payload["attack_type"],
                "confidence": "HIGH",
                "reasons": [f"Payload: {payload['match'][:60]}"], "flow": flow}
    if brute:
        return {"verdict": "ATTACK", "attack_type": brute["attack_type"],
                "confidence": brute["confidence"],
                "reasons": [brute["detail"]], "flow": flow}
    if exfil:
        return {"verdict": "ATTACK", "attack_type": exfil["attack_type"],
                "confidence": exfil["confidence"],
                "reasons": [exfil["detail"]], "flow": flow}
    if dns.get("suspicious"):
        return {"verdict": "ATTACK", "attack_type": dns["attack_type"],
                "confidence": "HIGH", "reasons": [dns["reason"]], "flow": flow}
    score, reasons = 0, []
    if fp.get("suspicious"):
        score += 3; reasons.append(fp.get("reason", "fp"))
    if http.get("is_http") and not http.get("is_real_browser"):
        score += 2; reasons.append(http.get("reason", "bad http"))
    if behavior.get("suspicious"):
        score += behavior["score"]; reasons.extend(behavior["reasons"])
    if score > 0:
        update_suspicion(src, score)
    cumulative = get_suspicion(src)
    if score >= 8 or (cumulative >= SUSPICION_ESCALATE_THRESHOLD and score >= 5):
        verdict, confidence = "ATTACK", "HIGH"
        if cumulative >= SUSPICION_ESCALATE_THRESHOLD:
            reasons.append(f"Cumulative suspicion score={cumulative:.1f}")
    elif score >= 3:
        verdict, confidence = "SUSPICIOUS", "MEDIUM"
    else:
        verdict, confidence = "LEGITIMATE", "LOW"
    attack_type = "ANOMALY"
    if verdict in ("ATTACK", "SUSPICIOUS"):
        is_syn_only = (TCP in pkt and pkt[TCP].flags & 0x02
                       and not pkt[TCP].flags & 0x10)
        has_http    = (TCP in pkt and pkt[TCP].dport == 80)
        match_str   = fp.get("match", "")
        up          = flow.get("unique_ports", 0)
        if match_str in ("TOOL", "SPOOFED", "RAW_SOCKET", "UNKNOWN") \
                or match_str.startswith("TOOL"):
            attack_type = "CRAFT_ATTACK"
        elif up > 15:
            attack_type = "PORT_SCAN"
        elif is_syn_only and has_http:
            attack_type = "HTTP_FLOOD"
        elif is_syn_only:
            attack_type = "SYN_FLOOD"
        elif ICMP in pkt:
            attack_type = "ICMP_FLOOD"
        elif UDP in pkt:
            attack_type = "UDP_FLOOD"
        elif any("unique destination ports" in r for r in reasons):
            attack_type = "PORT_SCAN"
    return {"verdict": verdict, "attack_type": attack_type,
            "confidence": confidence, "reasons": reasons, "flow": flow}


attack_state = defaultdict(lambda: {"active": False, "type": None})
state_lock   = threading.Lock()

def _handle_verdict(src_ip, verdict_result, pkt):
    v     = verdict_result["verdict"]
    atype = verdict_result["attack_type"]
    conf  = verdict_result["confidence"]
    reasons = verdict_result["reasons"]
    flow  = verdict_result.get("flow", {})
    extra = {
        "connection_count": flow.get("connection_count", 0),
        "flow_duration":    flow.get("flow_duration",    0.0),
        "unique_ports":     flow.get("unique_ports",     0),
        "syn_ack_ratio":    flow.get("syn_ack_ratio",    1.0),
        "payload_entropy":  (
            payload_entropy(bytes(pkt[Raw].load)) if Raw in pkt else 0.0
        ),
    }
    with state_lock:
        state = attack_state[src_ip]
        if v == "ATTACK" and not state["active"]:
            state["active"] = True; state["type"] = atype
            detail_str = "|".join(reasons[:3])
            log_event("ATTACK_START", atype, src_ip,
                      detail=detail_str, confidence=conf)
            send_alert(atype, src_ip, confidence=conf,
                       detail=detail_str, extra_state=extra)
        elif v == "SUSPICIOUS" and not state["active"]:
            detail_str = "|".join(reasons[:3])
            log_event("SUSPICIOUS", atype, src_ip,
                      detail=detail_str, confidence=conf)
        elif v == "LEGITIMATE" and state["active"]:
            state["active"] = False
            old_type = state["type"]
            log_event("ATTACK_END", old_type, src_ip,
                      detail="Traffic normalized", confidence="HIGH")
            send_alert("none", src_ip, confidence="HIGH",
                       detail="Traffic normalized")


def on_packet(pkt):
    src_ip = get_src_ip(pkt)
    if not src_ip: return
    if src_ip in WHITELIST_IPS:
        return
    try:
        update_profile(pkt)
        update_flow(pkt)
        fp = {"suspicious": False}
        if TCP in pkt and (pkt[TCP].flags & 0x02):
            fp = tcp_fingerprint(pkt)
        http_r = {"is_http": False, "is_real_browser": True}
        if TCP in pkt and pkt[TCP].dport in (80, 8080, 8443) and Raw in pkt:
            http_r = inspect_http(pkt)
        dns_r = {"suspicious": False}
        if (UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53)
                and DNS in pkt):
            dns_r = inspect_dns(pkt)
        payload_r   = {"hit": False}
        reassembled = get_reassembled_payload(pkt)
        if Raw in pkt:
            payload_r = scan_payload(pkt)
        if not payload_r["hit"] and reassembled:
            payload_r = scan_payload_bytes(reassembled, src_ip)
        behavior = analyze_behavior(src_ip)
        brute    = check_brute_force(pkt)
        exfil    = check_exfiltration(pkt)
        flow     = get_flow_state(src_ip)
        v = make_verdict(src_ip, pkt, fp, http_r, dns_r, payload_r,
                         behavior, brute=brute, exfil=exfil, flow=flow)
        _handle_verdict(src_ip, v, pkt)
    except Exception as e:
        log_event("ERROR", "PARSE_ERROR", "", detail=str(e)[:200])


def cleanup_loop():
    while True:
        try:
            now = time.time()
            with profiles_lock:
                to_delete = [ip for ip, p in ip_profiles.items()
                             if now - p["last_seen"] > 60]
                for ip in to_delete: del ip_profiles[ip]
            with _stream_lock:
                stale = [k for k, ts in _stream_last_seen.items()
                         if now - ts > STREAM_IDLE_TIMEOUT]
                for k in stale:
                    _tcp_streams.pop(k, None)
                    _stream_last_seen.pop(k, None)
            with _flows_lock:
                stale = [ip for ip, f in _flows.items()
                         if now - f["last_seen"] > 120]
                for ip in stale: del _flows[ip]
        except Exception:
            pass

        try:
            now = time.time()
            with _suspicion_lock:
                stale = [ip for ip, e in _suspicion_scores.items()
                         if now - e["last_update"] > 300]
                for ip in stale:
                    del _suspicion_scores[ip]

            with _exfil_lock:
                stale = [ip for ip, e in _exfil.items()
                         if e["start"] > 0 and now - e["start"] > EXFIL_WINDOW_SECONDS * 3]
                for ip in stale:
                    del _exfil[ip]

            with _brute_lock:
                stale = [ip for ip in _brute
                         if all(
                             len(q) == 0 or now - max(q) > 30
                             for q in _brute[ip].values()
                         )]
                for ip in stale:
                    del _brute[ip]

            with state_lock:
                stale = [ip for ip, s in attack_state.items()
                         if not s["active"]]
                for ip in stale:
                    del attack_state[ip]

        except Exception:
            pass

        time.sleep(30)


def main():
    global OFFLINE_MODE
    init_logger()
    iface = os.environ.get("MACDS_INTERFACE", INTERFACE)
    print(f"[*] MACDS DPI starting — interface: {iface}")
    print(f"[*] Log file: {LOG_FILE}")
    print(f"[*] Patterns: {len(PATTERNS)} | Brute ports: {list(BRUTE_PORTS.keys())}")
    try:
        import requests
        cp_url    = os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000")
        macds_key = os.environ.get("MACDS_API_KEY", "changeme-set-in-env")
        requests.get(f"{cp_url}/health",
                     headers={"X-MACDS-Key": macds_key}, timeout=3)
        print(f"[*] Control plane reachable at {cp_url}")
        start_polling()
    except Exception:
        print("[!] Control plane unreachable — OFFLINE_MODE active")
        OFFLINE_MODE = True
    threading.Thread(target=cleanup_loop, daemon=True).start()
    sniff(iface=iface, prn=on_packet, store=False, session=IPSession)

if __name__ == "__main__":
    main()
