#!/usr/bin/env python3
"""
MACDS end-to-end smoke test.
Run this on the Mac AFTER docker-compose up to verify the full API loop.
Does not require Mininet or Ubuntu.

Usage:
    python3 test_flow.py
"""

import os
import sys
import time
import requests

CONTROL_PLANE_URL = "http://127.0.0.1:8000"
API_KEY = os.environ.get("MACDS_API_KEY", "testkey123")

passed = 0
failed = 0


def check(label: str, condition: bool):
    global passed, failed
    if condition:
        print(f"  [PASS] {label}")
        passed += 1
    else:
        print(f"  [FAIL] {label}")
        failed += 1


def step(title: str):
    print(f"\n{'─' * 54}")
    print(f"  {title}")
    print(f"{'─' * 54}")


# ── 0. Health ──────────────────────────────────────────────
step("0 — Health check")
try:
    r = requests.get(f"{CONTROL_PLANE_URL}/health", timeout=3)
    check("Control plane reachable", r.status_code == 200)
    check("Health response OK", r.json().get("status") == "ok")
except requests.exceptions.ConnectionError:
    print(f"\n[!] Cannot reach {CONTROL_PLANE_URL}")
    print("    Run:  cd control_plane && docker-compose up -d --build")
    sys.exit(1)

# ── 1. Train agents first ──────────────────────────────────
step("1 — Pre-train agents via /api/train")
# headers
r = requests.post(
    f"{CONTROL_PLANE_URL}/api/train?rounds=300",
    headers={"X-MACDS-Key": API_KEY},
    timeout=30
)
check("POST /api/train 200", r.status_code == 200)
data = r.json()
print(f"       block_ip rate: {data.get('block_ip_rate')}")
check("block_ip rate > 90%", float(data.get("block_ip_rate", "0%").rstrip("%")) > 90) # FIX: changed > 80% to > 90%

# ── 2. SYN flood → block_ip ───────────────────────────────
step("2 — SYN flood detected → block_ip expected")
payload = {
    "timestamp": time.time(),
    "attack_type": "SYN_FLOOD",
    "source_ip": "10.0.0.3",
    "packet_rate": 2000.0,
}
r = requests.post(f"{CONTROL_PLANE_URL}/api/logs", json=payload,
                  headers={"X-MACDS-Key": API_KEY}, timeout=3)
check("POST /api/logs 200", r.status_code == 200)
data = r.json()
print(f"       action_decided: {data.get('action_decided')}")
check("action_decided is block_ip", data.get("action_decided") == "block_ip")

# ── 3. Pull block action ───────────────────────────────────
step("3 — Execution plane polls for block action")
time.sleep(0.3)
r = requests.get(f"{CONTROL_PLANE_URL}/api/action",
                 headers={"X-MACDS-Key": API_KEY}, timeout=3)
check("GET /api/action 200", r.status_code == 200)
action_data = r.json()
check("action is block_ip", action_data.get("action") == "block_ip")
check("target_ip matches attacker", action_data.get("target_ip") == "10.0.0.3")
if action_data.get("action") == "block_ip":
    print(f"       → iptables -I INPUT -s {action_data['target_ip']} -j DROP")

# ── 4. Attack resolves → unblock_ip ───────────────────────
step("4 — Attack resolved → unblock_ip expected")
payload = {
    "timestamp": time.time(),
    "attack_type": "none",
    "source_ip": "10.0.0.3",
    "packet_rate": 5.0,
}
r = requests.post(f"{CONTROL_PLANE_URL}/api/logs", json=payload,
                  headers={"X-MACDS-Key": API_KEY}, timeout=3)
check("POST /api/logs 200", r.status_code == 200)
check("action_decided is unblock_ip", r.json().get("action_decided") == "unblock_ip")

# ── 5. Pull unblock action ─────────────────────────────────
step("5 — Execution plane polls for unblock action")
time.sleep(0.3)
r = requests.get(f"{CONTROL_PLANE_URL}/api/action",
                 headers={"X-MACDS-Key": API_KEY}, timeout=3)
check("GET /api/action 200", r.status_code == 200)
action_data = r.json()
check("action is unblock_ip", action_data.get("action") == "unblock_ip")
check("target_ip matches attacker", action_data.get("target_ip") == "10.0.0.3")
if action_data.get("action") == "unblock_ip":
    print(f"       → iptables -D INPUT -s {action_data['target_ip']} -j DROP")

# ── 6. Queue empty ─────────────────────────────────────────
step("6 — Verify action queue is empty")
r = requests.get(f"{CONTROL_PLANE_URL}/api/action",
                 headers={"X-MACDS-Key": API_KEY}, timeout=3)
check("Queue empty — action is none", r.json().get("action") == "none")

# ── Summary ────────────────────────────────────────────────
print(f"\n{'=' * 54}")
print(f"  Results: {passed} passed, {failed} failed")
print(f"{'=' * 54}\n")
sys.exit(0 if failed == 0 else 1)
