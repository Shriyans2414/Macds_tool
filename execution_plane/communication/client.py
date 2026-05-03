"""
MACDS Execution Plane communication client.
Sends attack logs to the Control Plane and polls for enforcement actions.

IMPORTANT: CONTROL_PLANE_URL must be the Mac's LAN IP, not localhost.
Set it before running: sudo CONTROL_PLANE_URL=http://<MAC_IP>:8000 python3 ...
"""

import os
import time
import subprocess
import threading
import ipaddress
import sys

import requests

try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from sdn.ryu_enforcer import push_block_flow, delete_block_flow
except ImportError:
    pass

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000")
MACDS_API_KEY = os.environ.get("MACDS_API_KEY", "changeme-set-in-env")
HEADERS = {"X-MACDS-Key": MACDS_API_KEY}
SDN_MODE = os.environ.get("SDN_MODE", "false").lower() == "true"

_MAX_RETRIES = 3
_RETRY_DELAY = 0.5

def _is_ipv6(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return False

def _rule_exists(target_ip: str) -> bool:
    cmd = "ip6tables" if _is_ipv6(target_ip) else "iptables"
    res = subprocess.run(
        [cmd, "-C", "INPUT", "-s", target_ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return res.returncode == 0

def send_log(attack_type: str, src_ip: str, packet_rate: float = 0.0,
             confidence: str = "MEDIUM", detail: str = "",
             connection_count: float = 5.0,
             flow_duration: float = 2.0,
             unique_ports: float = 3.0,
             syn_ack_ratio: float = 0.95,
             payload_entropy: float = 3.5,
             **kwargs):
    """Send an attack event to the Control Plane with retry logic."""
    url = f"{CONTROL_PLANE_URL}/api/logs"
    payload = {
        "timestamp":        time.time(),
        "attack_type":      attack_type,
        "source_ip":        src_ip,
        "packet_rate":      packet_rate,
        "confidence":       confidence,
        "detail":           detail[:500],
        "connection_count": connection_count,
        "flow_duration":    flow_duration,
        "unique_ports":     unique_ports,
        "syn_ack_ratio":    syn_ack_ratio,
        "payload_entropy":  payload_entropy,
    }
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = requests.post(url, headers=HEADERS, json=payload, timeout=2)
            resp.raise_for_status()
            print(f"[CLIENT] Log sent: {attack_type} from {src_ip}")
            return
        except Exception as e:
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
            else:
                print(f"[CLIENT ERROR] Failed after {_MAX_RETRIES} attempts: {e}")


def execute_action(action_data: dict):
    """Execute an iptables rule based on the control plane's decision."""
    action = action_data.get("action")
    target_ip = action_data.get("target_ip")

    if not target_ip:
        return

    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"[SECURITY] Invalid IP rejected: {target_ip!r}")
        return

    cmd = "ip6tables" if _is_ipv6(target_ip) else "iptables"

    if action == "block_ip":
        print(f"[CLIENT] Blocking {target_ip}")
        if SDN_MODE:
            push_block_flow(target_ip)
        else:
            if not _rule_exists(target_ip):
                res = subprocess.run(
                    [cmd, "-I", "INPUT", "-s", target_ip, "-j", "DROP"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                if res.returncode != 0:
                    print(f"[CLIENT ERROR] {cmd} failed (not root?): {res.stderr.decode().strip()}")
            else:
                print(f"[CLIENT] {target_ip} already blocked — skipping duplicate rule")
    elif action in ("unblock_ip", "recover_ip"):
        print(f"[CLIENT] Unblocking {target_ip}")
        if SDN_MODE:
            delete_block_flow(target_ip)
        else:
            res = subprocess.run(
                [cmd, "-D", "INPUT", "-s", target_ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if res.returncode != 0:
                print(f"[CLIENT ERROR] {cmd} failed (not root?): {res.stderr.decode().strip()}")
    elif action == "raise_alert":
        print(f"[CLIENT] ALERT raised for {target_ip} — no target change")


def poll_actions():
    """Poll Control Plane for enforcement actions every second."""
    url = f"{CONTROL_PLANE_URL}/api/action"
    print(f"[*] Polling {url} for actions")
    while True:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                if data and data.get("action") not in (None, "none", "do_nothing"):
                    execute_action(data)
        except Exception:
            pass
        time.sleep(1.0)


def start_polling():
    """Start the polling loop in a background daemon thread."""
    threading.Thread(target=poll_actions, daemon=True).start()
