import requests
import json

RYU_REST_URL = "http://127.0.0.1:8080/stats/flowentry/add"
RYU_DELETE_URL = "http://127.0.0.1:8080/stats/flowentry/delete"

def push_block_flow(ip: str, dpid: int = 1):
    payload = {
        "dpid": dpid,
        "cookie": 1,
        "cookie_mask": 1,
        "table_id": 0,
        "idle_timeout": 0,
        "hard_timeout": 0,
        "priority": 100,
        "flags": 1,
        "match": {
            "nw_src": ip,
            "eth_type": 2048 # IPv4
        },
        "actions": [] # Empty actions means DROP in OpenFlow
    }
    try:
        resp = requests.post(RYU_REST_URL, json=payload, timeout=2)
        if resp.status_code == 200:
            print(f"[SDN] Added OpenFlow DROP rule for {ip}")
        else:
            print(f"[SDN ERROR] Failed to add rule: {resp.text}")
    except Exception as e:
        print(f"[SDN ERROR] Connection to Ryu failed: {e}")

def delete_block_flow(ip: str, dpid: int = 1):
    payload = {
        "dpid": dpid,
        "cookie": 1,
        "cookie_mask": 1,
        "table_id": 0,
        "idle_timeout": 0,
        "hard_timeout": 0,
        "priority": 100,
        "flags": 1,
        "match": {
            "nw_src": ip,
            "eth_type": 2048
        },
        "actions": []
    }
    try:
        resp = requests.post(RYU_DELETE_URL, json=payload, timeout=2)
        if resp.status_code == 200:
            print(f"[SDN] Removed OpenFlow DROP rule for {ip}")
        else:
            print(f"[SDN ERROR] Failed to remove rule: {resp.text}")
    except Exception as e:
        print(f"[SDN ERROR] Connection to Ryu failed: {e}")
