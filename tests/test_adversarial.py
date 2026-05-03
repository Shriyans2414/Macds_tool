from execution_plane.ids.deep_packet_inspector import make_verdict, update_suspicion, get_suspicion, analyze_behavior, ip_profiles, scan_payload_bytes
from scapy.all import IP, TCP, Raw

def test_fragmented_sql():
    # Simulate fragmented SQL passing through scan_payload_bytes
    raw_bytes = b"UNI" + b"ON SE" + b"LECT"
    res = scan_payload_bytes(raw_bytes, "10.0.0.5")
    assert res["hit"] is True
    assert res["attack_type"] == "SQL_INJECTION"

def test_low_rate_suspicion_accumulation():
    # 10 x 0.9 delta events
    ip = "10.0.0.77"
    for _ in range(10):
        update_suspicion(ip, 0.9)
    
    score = get_suspicion(ip)
    assert score > 8.0

    pkt = IP(src=ip, dst="10.0.0.1")/TCP(sport=1234, dport=80)
    fp = {"suspicious": False}
    http = {"is_http": True, "is_real_browser": True}
    dns = {"suspicious": False}
    payload = {"hit": False}
    behavior = {"suspicious": True, "score": 3, "reasons": []}
    
    res = make_verdict(ip, pkt, fp, http, dns, payload, behavior)
    assert res["verdict"] == "ATTACK"
    assert res["confidence"] == "HIGH"

def test_window_spoof_behavioral():
    ip = "10.0.0.88"
    import time
    from execution_plane.ids.deep_packet_inspector import profiles_lock
    
    now = time.time()
    with profiles_lock:
        ip_profiles[ip]["syn_ts"].extend([now] * 40)
        ip_profiles[ip]["ports"] = set(range(1000, 1015))
        
    res = analyze_behavior(ip)
    assert res["suspicious"] is True
    assert res["score"] >= 4
