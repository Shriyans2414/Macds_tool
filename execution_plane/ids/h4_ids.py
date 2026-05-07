#!/usr/bin/env python3
"""
MACDS IDS — runs on Ubuntu host, sniffing the Mininet switch interface s1-eth3.

WHY s1-eth3 and not h4-eth0:
  - h4-eth0 only exists inside h4's Mininet network namespace
  - The IDS runs in a plain Ubuntu shell (not inside the namespace)
  - s1-eth3 is the OVS switch port connected to h3 (the attacker)
  - All traffic FROM h3 passes through s1-eth3 — perfect for detection
  - Sniffing s1-eth3 from the host requires sudo but no namespace tricks

HOW TO RUN (plain Ubuntu shell, not inside Mininet CLI):
  sudo CONTROL_PLANE_URL=http://<MAC_IP>:8000 python3 execution_plane/ids/h4_ids.py

DO NOT use sudo -E (ignored on this Ubuntu config).
DO NOT run inside Mininet namespace (no network route to Mac from there).
"""

import os
import sys
import csv
import time
import threading
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, ICMP, UDP

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from communication.client import send_log, start_polling
except ImportError:
    print("[ERROR] Cannot import communication.client.")
    print("        Run from the macds-main project root directory.")
    sys.exit(1)

# ── Configuration ──────────────────────────────────────────────────────────────
# s1-eth3 is the switch port connected to h3 (attacker).
# All packets FROM h3 traverse this interface.
INTERFACE = "s1-eth3"

SHORT_WINDOW  = 2.0   # seconds — window for ICMP/flood detection
LONG_WINDOW   = 30.0  # seconds — how long to keep packets in buffer
CHECK_INTERVAL = 1.0  # seconds — detection loop cadence

# Thresholds tuned for VM/Mininet testing environment.
# Raise these for production hardware (e.g. 300/400/500).
ICMP_PPS_THRESHOLD      = 10
TCP_SYN_PPS_THRESHOLD   = 20
UDP_PPS_THRESHOLD       = 20
PORTSCAN_PORT_THRESHOLD = 5     # unique ports hit by one IP within 2 seconds
HTTP_FLOOD_THRESHOLD    = 20    # TCP port-80 packets per second
LAND_ATTACK_THRESHOLD   = 1     # even 1 land packet is an attack

LOG_DIR  = "logs"
LOG_FILE = "logs/ids_events.csv"

# ── Shared state ───────────────────────────────────────────────────────────────
packet_buffer: deque = deque()
buffer_lock = threading.Lock()

attack_state = {
    "icmp_flood":  False,
    "syn_flood":   False,
    "udp_flood":   False,
    "port_scan":   False,
    "http_flood":  False,
    "land_attack": False,
}

# Track which IP triggered each attack type so we can send the correct
# source IP in the ATTACK_END alert. Without this, when traffic drops to
# zero, syn_counts is empty and we have no IP to reference.
_last_attacker: dict = {
    "icmp_flood":  None,
    "syn_flood":   None,
    "udp_flood":   None,
    "port_scan":   None,
    "http_flood":  None,
    "land_attack": None,
}

OFFLINE_MODE = False

# ── Logging ────────────────────────────────────────────────────────────────────

def init_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "event_type", "attack_type", "src_ip"])


def log_event(event: str, attack: str, src: str):
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([time.time(), event, attack, src])


# ── Control plane notification ─────────────────────────────────────────────────

def send_alert(attack_type: str, src_ip: str, packet_rate: float = 0.0,
               connection_count: float = 0.0,
               flow_duration: float = 0.3,
               unique_ports: float = 1.0,
               syn_ack_ratio: float = 0.05,
               payload_entropy: float = 1.0):
    """
    Send alert to control plane.
    Note: flow_duration, unique_ports, syn_ack_ratio, payload_entropy
    are calibrated approximations for rate-based detections.
    h4_ids operates at packet-count level and cannot measure
    per-packet flow features — the DPI sends real measured values.
    Approximations: floods have short flows (0.3s), low ACK ratio
    (0.05), single target port (1), low payload entropy (1.0).
    """
    if OFFLINE_MODE:
        return
    send_log(attack_type, src_ip, packet_rate=packet_rate, connection_count=connection_count, flow_duration=flow_duration, unique_ports=unique_ports, syn_ack_ratio=syn_ack_ratio, payload_entropy=payload_entropy)


# ── Packet capture ─────────────────────────────────────────────────────────────

def on_packet(pkt):
    if IP in pkt:
        with buffer_lock:
            packet_buffer.append((time.time(), pkt))


# ── Attack detection ───────────────────────────────────────────────────────────

def detect_syn_flood(packets: list):
    """
    Count SYN packets per source IP in the last 1 second.

    ATTACK START: any source exceeds TCP_SYN_PPS_THRESHOLD
    ATTACK END:   the previously seen attacker's count drops below threshold
                  OR no SYN packets seen at all (flood stopped completely)

    _last_attacker["syn_flood"] is critical — without it, when the flood stops
    syn_counts is empty, we have no IP to iterate over, and ATTACK_END never fires.
    """
    now = time.time()
    syn_counts: dict = defaultdict(int)

    for ts, pkt in packets:
        if TCP in pkt and (pkt[TCP].flags & 0x02) and now - ts <= 1.0:
            syn_counts[pkt[IP].src] += 1

    if not attack_state["syn_flood"]:
        # Not currently under attack — check if one is starting
        for src_ip, count in syn_counts.items():
            if count >= TCP_SYN_PPS_THRESHOLD:
                attack_state["syn_flood"] = True
                _last_attacker["syn_flood"] = src_ip
                print(f"[ATTACK START] SYN FLOOD from {src_ip} ({count} pps)")
                log_event("ATTACK_START", "SYN_FLOOD", src_ip)
                send_alert("SYN_FLOOD", src_ip, packet_rate=float(count), connection_count=float(count), flow_duration=0.3, unique_ports=1, syn_ack_ratio=0.05, payload_entropy=1.0)
                break
    else:
        # Currently under attack — check if it ended
        src_ip = _last_attacker["syn_flood"]
        current_count = syn_counts.get(src_ip, 0)
        if current_count < TCP_SYN_PPS_THRESHOLD:
            attack_state["syn_flood"] = False
            print(f"[ATTACK END] SYN FLOOD ended from {src_ip}")
            log_event("ATTACK_END", "SYN_FLOOD", src_ip)
            send_alert("none", src_ip)


def detect_ddos(packets: list):
    """
    Count ICMP packets per source IP in the last SHORT_WINDOW seconds.
    Same _last_attacker pattern as detect_syn_flood.
    """
    now = time.time()
    icmp_counts: dict = defaultdict(int)

    for ts, pkt in packets:
        if ICMP in pkt and now - ts <= SHORT_WINDOW:
            icmp_counts[pkt[IP].src] += 1

    if not attack_state["icmp_flood"]:
        for src_ip, count in icmp_counts.items():
            if count >= ICMP_PPS_THRESHOLD:
                attack_state["icmp_flood"] = True
                _last_attacker["icmp_flood"] = src_ip
                print(f"[ATTACK START] ICMP_FLOOD from {src_ip} ({count} pps)")
                log_event("ATTACK_START", "ICMP_FLOOD", src_ip)
                send_alert("ICMP_FLOOD", src_ip, packet_rate=float(count),
                           connection_count=float(count),
                           flow_duration=0.3, unique_ports=1,
                           syn_ack_ratio=0.05, payload_entropy=1.0)
                break
    else:
        src_ip = _last_attacker["icmp_flood"]
        current_count = icmp_counts.get(src_ip, 0)
        if current_count < ICMP_PPS_THRESHOLD:
            attack_state["icmp_flood"] = False
            print(f"[ATTACK END] ICMP_FLOOD ended from {src_ip}")
            log_event("ATTACK_END", "ICMP_FLOOD", src_ip)
            send_alert("none", src_ip)


def detect_udp_flood(packets: list):
    """
    Count UDP packets per source IP in the last 1 second.
    Same _last_attacker pattern as detect_syn_flood.
    """
    now = time.time()
    udp_counts: dict = defaultdict(int)

    for ts, pkt in packets:
        if UDP in pkt and now - ts <= 1.0:
            udp_counts[pkt[IP].src] += 1

    if not attack_state["udp_flood"]:
        for src_ip, count in udp_counts.items():
            if count >= UDP_PPS_THRESHOLD:
                attack_state["udp_flood"] = True
                _last_attacker["udp_flood"] = src_ip
                print(f"[ATTACK START] UDP FLOOD from {src_ip} ({count} pps)")
                log_event("ATTACK_START", "UDP_FLOOD", src_ip)
                send_alert("UDP_FLOOD", src_ip, packet_rate=float(count), connection_count=float(count), flow_duration=0.3, unique_ports=1, syn_ack_ratio=0.05, payload_entropy=1.0)
                break
    else:
        src_ip = _last_attacker["udp_flood"]
        current_count = udp_counts.get(src_ip, 0)
        if current_count < UDP_PPS_THRESHOLD:
            attack_state["udp_flood"] = False
            print(f"[ATTACK END] UDP FLOOD ended from {src_ip}")
            log_event("ATTACK_END", "UDP_FLOOD", src_ip)
            send_alert("none", src_ip)


def detect_port_scan(packets: list):
    """
    Port scan detection: one source IP hitting many different destination
    ports within a 2-second window.
    Even a slow scan (1 port per second) is caught within SHORT_WINDOW.
    Trigger: PORTSCAN_PORT_THRESHOLD unique ports from one source.

    Test with:  mininet> h3 nmap -sS --host-timeout 10s 10.0.0.4
    """
    now = time.time()
    # Map: src_ip -> set of destination ports seen in SHORT_WINDOW
    port_sets: dict = defaultdict(set)

    for ts, pkt in packets:
        if TCP in pkt and now - ts <= SHORT_WINDOW:
            port_sets[pkt[IP].src].add(pkt[TCP].dport)

    if not attack_state["port_scan"]:
        for src_ip, ports in port_sets.items():
            if len(ports) >= PORTSCAN_PORT_THRESHOLD:
                attack_state["port_scan"] = True
                _last_attacker["port_scan"] = src_ip
                print(f"[ATTACK START] PORT SCAN from {src_ip} ({len(ports)} ports in {SHORT_WINDOW}s)")
                log_event("ATTACK_START", "PORT_SCAN", src_ip)
                send_alert("PORT_SCAN", src_ip, packet_rate=float(len(ports)),
                           connection_count=float(len(ports)),
                           flow_duration=0.5,
                           unique_ports=float(len(ports)),
                           syn_ack_ratio=0.1,
                           payload_entropy=0.0)
                break
    else:
        src_ip = _last_attacker["port_scan"]
        current_ports = len(port_sets.get(src_ip, set()))
        if current_ports < PORTSCAN_PORT_THRESHOLD:
            attack_state["port_scan"] = False
            print(f"[ATTACK END] PORT SCAN ended from {src_ip}")
            log_event("ATTACK_END", "PORT_SCAN", src_ip)
            send_alert("none", src_ip)


def detect_http_flood(packets: list):
    """
    HTTP flood detection: high rate of TCP packets to port 80 from one source.
    Targets web servers specifically — different from generic SYN flood because
    it counts ALL TCP packets to port 80 (SYN, ACK, PSH) not just SYN.
    Threshold: HTTP_FLOOD_THRESHOLD packets/second to port 80.

    Test with:  mininet> h3 hping3 -p 80 -S --faster 10.0.0.4
    """
    now = time.time()
    http_counts: dict = defaultdict(int)

    for ts, pkt in packets:
        if TCP in pkt and pkt[TCP].dport == 80 and now - ts <= 1.0:
            flags = pkt[TCP].flags # FIX: capture tcp flags
            if (flags & 0x02) and not (flags & 0x10): # FIX: skip pure SYN packets to avoid double detect
                continue # FIX: skip pure SYN packets
            http_counts[pkt[IP].src] += 1

    if not attack_state["http_flood"]:
        for src_ip, count in http_counts.items():
            if count >= HTTP_FLOOD_THRESHOLD:
                attack_state["http_flood"] = True
                _last_attacker["http_flood"] = src_ip
                print(f"[ATTACK START] HTTP FLOOD from {src_ip} ({count} pps to port 80)")
                log_event("ATTACK_START", "HTTP_FLOOD", src_ip)
                send_alert("HTTP_FLOOD", src_ip, packet_rate=float(count), connection_count=float(count), flow_duration=0.3, unique_ports=1, syn_ack_ratio=0.05, payload_entropy=1.0)
                break
    else:
        src_ip = _last_attacker["http_flood"]
        current_count = http_counts.get(src_ip, 0)
        if current_count < HTTP_FLOOD_THRESHOLD:
            attack_state["http_flood"] = False
            print(f"[ATTACK END] HTTP FLOOD ended from {src_ip}")
            log_event("ATTACK_END", "HTTP_FLOOD", src_ip)
            send_alert("none", src_ip)


def detect_land_attack(packets: list):
    """
    Land attack detection: packets where source IP equals destination IP.
    This causes the victim to send replies to itself in an infinite loop,
    exhausting resources. Even a single such packet is malicious.
    Any packet with src == dst is immediately flagged.

    Test with:  mininet> h3 hping3 -S -a 10.0.0.4 10.0.0.4 -p 80
    """
    now = time.time()

    for ts, pkt in packets:
        if IP in pkt and now - ts <= 1.0:
            if pkt[IP].src == pkt[IP].dst:
                src_ip = pkt[IP].src
                if not attack_state["land_attack"]:
                    attack_state["land_attack"] = True
                    _last_attacker["land_attack"] = src_ip
                    print(f"[ATTACK START] LAND ATTACK detected (src==dst={src_ip})")
                    log_event("ATTACK_START", "LAND_ATTACK", src_ip)
                    send_alert("LAND_ATTACK", src_ip, packet_rate=1.0, connection_count=1.0, flow_duration=0.3, unique_ports=1, syn_ack_ratio=0.05, payload_entropy=1.0)
                return  # One match is enough — no need to keep scanning

    # No land packets seen in this window — clear the state
    if attack_state["land_attack"]:
        src_ip = _last_attacker["land_attack"]
        attack_state["land_attack"] = False
        print(f"[ATTACK END] LAND ATTACK ended from {src_ip}")
        log_event("ATTACK_END", "LAND_ATTACK", src_ip)
        send_alert("none", src_ip)


# ── Main detection loop ────────────────────────────────────────────────────────

def detection_loop():
    while True:
        now = time.time()
        with buffer_lock:
            # Expire old packets
            while packet_buffer and now - packet_buffer[0][0] > LONG_WINDOW:
                packet_buffer.popleft()
            packets = list(packet_buffer)

        detect_syn_flood(packets)
        detect_ddos(packets)
        detect_udp_flood(packets)
        detect_port_scan(packets)
        detect_http_flood(packets)
        detect_land_attack(packets)

        time.sleep(CHECK_INTERVAL)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    global OFFLINE_MODE

    init_logger()
    print("[*] MACDS IDS starting")
    print(f"[*] Sniffing interface: {INTERFACE}")
    print(f"[*] Log file: {LOG_FILE}")
    print(f"[*] Thresholds: SYN={TCP_SYN_PPS_THRESHOLD} UDP={UDP_PPS_THRESHOLD} ICMP={ICMP_PPS_THRESHOLD} pps")

    # Test control plane connectivity BEFORE starting anything else
    try:
        import requests as req
        cp_url = os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000")
        req.get(f"{cp_url}/health", timeout=3)
        print(f"[*] Control plane reachable at {cp_url}")
        start_polling()
    except Exception:
        print("[!] Control plane unreachable — OFFLINE_MODE active (detection only, no enforcement)")
        OFFLINE_MODE = True

    # Start Scapy sniff in background daemon thread
    threading.Thread(
        target=sniff,
        kwargs={"iface": INTERFACE, "prn": on_packet, "store": False},
        daemon=True,
    ).start()

    detection_loop()


if __name__ == "__main__":
    main()
