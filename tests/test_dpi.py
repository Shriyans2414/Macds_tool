from scapy.all import IP, TCP, Raw
from execution_plane.ids.deep_packet_inspector import make_verdict, get_reassembled_payload, _tcp_streams, update_suspicion, get_suspicion

def test_make_verdict_clean():
    pkt = IP(src="1.2.3.4", dst="4.3.2.1")/TCP(sport=1234, dport=80)/Raw(b"GET / HTTP/1.1\r\n\r\n")
    fp = {"suspicious": False}
    http = {"is_http": True, "is_real_browser": True}
    dns = {"suspicious": False}
    payload = {"hit": False}
    behavior = {"suspicious": False, "score": 0, "reasons": []}
    
    res = make_verdict("1.2.3.4", pkt, fp, http, dns, payload, behavior)
    assert res["verdict"] == "LEGITIMATE"
    assert res["confidence"] == "LOW"

def test_make_verdict_syn_flood():
    pkt = IP(src="1.2.3.4", dst="4.3.2.1")/TCP(sport=1234, dport=1234, flags="S")
    fp = {"suspicious": False}
    http = {"is_http": False, "is_real_browser": True}
    dns = {"suspicious": False}
    payload = {"hit": False}
    behavior = {"suspicious": True, "score": 4, "reasons": []}
    
    res = make_verdict("1.2.3.4", pkt, fp, http, dns, payload, behavior)
    assert res["verdict"] == "SUSPICIOUS" # Score 4 => SUSPICIOUS (>=3)
    assert res["attack_type"] == "SYN_FLOOD"

def test_reassembly():
    pkt1 = IP(src="192.168.1.5", dst="10.0.0.1")/TCP(sport=1111, dport=80)/Raw(b"UN")
    pkt2 = IP(src="192.168.1.5", dst="10.0.0.1")/TCP(flags="P", sport=1111, dport=80)/Raw(b"ION")
    
    get_reassembled_payload(pkt1)
    res = get_reassembled_payload(pkt2)
    assert res == b"UNION"

def test_suspicion_accumulation():
    update_suspicion("10.0.0.100", 3.0)
    assert abs(get_suspicion("10.0.0.100") - 3.0) < 0.1
    
    update_suspicion("10.0.0.100", 5.0)
    assert get_suspicion("10.0.0.100") >= 7.8
