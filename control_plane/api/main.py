import os
import time
import threading
import ipaddress
import queue
import logging
from logging.handlers import RotatingFileHandler
from contextlib import asynccontextmanager
from decimal import Decimal

import boto3
import redis as redis_client
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from macds.agents.multi_agent import MultiAgentSystem
from api.federation import handle_federation

MACDS_API_KEY = os.environ.get("MACDS_API_KEY", "changeme-set-in-env")
QTABLE_DIR = os.environ.get("QTABLE_DIR", "/app/qtables")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

CONFIDENCE_MULT = {"HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5}
BLOCK_ON_SIGHT = {
    "SYN_FLOOD","UDP_FLOOD","ICMP_FLOOD","HTTP_FLOOD","LAND_ATTACK",
    "SQL_INJECTION","XSS","PATH_TRAVERSAL","LOG4SHELL","SHELLSHOCK",
    "CMD_INJECTION","SSRF","DNS_AMPLIFICATION","DNS_DGA","PORT_SCAN","CRAFT_ATTACK",
    "SSH_BRUTE_FORCE","RDP_BRUTE_FORCE","FTP_BRUTE_FORCE",
    "DATA_EXFILTRATION","SPRING4SHELL","STRUTS_RCE",
    "PHP_INJECTION","XXE","SSTI",
}


try:
    _redis = redis_client.from_url(REDIS_URL, decode_responses=True)
    _redis.ping()
    REDIS_OK = True
except Exception:
    REDIS_OK = False
    print("[WARN] Redis unavailable — falling back to in-memory pending_actions")

try:
    dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
    table = dynamodb.Table("macds-attack-history")
    _dynamo_ok = True
except Exception:
    _dynamo_ok = False
    print("[WARN] DynamoDB unavailable")

_lock = threading.Lock()
pending_actions = {}
_last_attack_state: dict[str, dict] = {}
_block_timestamps: dict[str, float] = {}

def push_action(ip: str, action: str):
    if REDIS_OK:
        _redis.hset("macds:pending", ip, action)
    else:
        with _lock:
            pending_actions[ip] = action

def pop_action():
    if REDIS_OK:
        items = _redis.hgetall("macds:pending")
        if items:
            ip, action = next(iter(items.items()))
            _redis.hdel("macds:pending", ip)
            return ip, action
        return None, None
    else:
        with _lock:
            if pending_actions:
                ip = next(iter(pending_actions))
                return ip, pending_actions.pop(ip)
        return None, None

LOG_FILE = "logs/api_events.csv"
os.makedirs("logs", exist_ok=True)
_log_queue: queue.Queue = queue.Queue(maxsize=10000)

def log_event(event: str, attack: str, src: str, detail: str = "", confidence: str = ""):
    try:
        _log_queue.put_nowait({
            "timestamp": time.time(),
            "event": event,
            "attack": attack,
            "src": src,
            "detail": detail,
            "confidence": confidence,
        })
    except queue.Full:
        pass

def _log_writer():
    handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
    while True:
        try:
            entry = _log_queue.get(timeout=1.0)
            row = f"{entry['timestamp']},{entry['event']},{entry['attack']},{entry['src']},{entry['confidence']},{entry['detail'][:200]}\n"
            handler.stream.write(row)
            handler.stream.flush()
        except queue.Empty:
            pass
        except Exception as e:
            print(f"[LOG WRITER ERROR] {e}")

_dedup_cache: dict = {}
DEDUP_TTL = 10.0

def _cleanup_block_timestamps():
    while True:
        time.sleep(60)
        cutoff = time.time() - 300
        with _lock:
            stale = [ip for ip, ts in _block_timestamps.items() if ts < cutoff]
            for ip in stale:
                del _block_timestamps[ip]
        stale_dedup = [k for k, (ts, _) in list(_dedup_cache.items()) if time.time() - ts > DEDUP_TTL]
        for k in stale_dedup:
            _dedup_cache.pop(k, None)

threading.Thread(target=_cleanup_block_timestamps, daemon=True).start()
threading.Thread(target=_log_writer, daemon=True).start()

packets_inspected = Counter("macds_packets_inspected_total", "Total packets inspected")
blocks_total = Counter("macds_blocks_total", "Total IPs blocked")
agent_overrides = Counter("macds_agent_override_total", "Forced block overrides where agents voted do_nothing on HIGH-confidence attack")
agent_epsilon = Gauge("macds_agent_epsilon", "Agent epsilon value", ["agent"])

agents = MultiAgentSystem()

def _silent_pretrain(agents_, rounds=1000):
    S = {"connection_count":5,"flow_duration":2.0,
         "unique_ports":3,"syn_ack_ratio":0.95,"payload_entropy":3.5}
    scenarios = [
        ({**S,"packet_rate":3000,"cpu_usage":95,"bandwidth_usage":99,
          "attack_type":"syn_flood","connection_count":5000,
          "flow_duration":0.1,"unique_ports":1,"syn_ack_ratio":0.02,
          "payload_entropy":1.0}, "block_ip", 2.0),
        ({**S,"packet_rate":2500,"cpu_usage":85,"bandwidth_usage":95,
          "attack_type":"udp_flood","connection_count":3000,
          "flow_duration":0.05,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":7.5}, "block_ip", 2.0),
        ({**S,"packet_rate":2000,"cpu_usage":80,"bandwidth_usage":90,
          "attack_type":"icmp_flood","connection_count":2000,
          "flow_duration":0.01,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":0.5}, "block_ip", 2.0),
        ({**S,"packet_rate":1500,"cpu_usage":75,"bandwidth_usage":85,
          "attack_type":"http_flood","connection_count":1500,
          "flow_duration":0.3,"unique_ports":1,"syn_ack_ratio":0.5,
          "payload_entropy":4.5}, "block_ip", 2.0),
        ({**S,"packet_rate":200,"cpu_usage":30,"bandwidth_usage":20,
          "attack_type":"port_scan","connection_count":200,
          "flow_duration":0.1,"unique_ports":500,"syn_ack_ratio":0.1,
          "payload_entropy":0.0}, "raise_alert", 1.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"sql_injection","connection_count":3,
          "flow_duration":1.5,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.2}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"xss","connection_count":3,"flow_duration":1.0,
          "unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.0}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"path_traversal","connection_count":2,
          "flow_duration":0.8,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":3.8}, "block_ip", 2.0),
        ({**S,"packet_rate":20,"cpu_usage":15,"bandwidth_usage":5,
          "attack_type":"log4shell","connection_count":1,
          "flow_duration":0.5,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":5.5}, "block_ip", 2.0),
        ({**S,"packet_rate":20,"cpu_usage":15,"bandwidth_usage":5,
          "attack_type":"shellshock","connection_count":1,
          "flow_duration":0.3,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.8}, "block_ip", 2.0),
        ({**S,"packet_rate":20,"cpu_usage":15,"bandwidth_usage":5,
          "attack_type":"cmd_injection","connection_count":1,
          "flow_duration":0.4,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.5}, "block_ip", 2.0),
        ({**S,"packet_rate":30,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"ssrf","connection_count":2,"flow_duration":1.0,
          "unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.3}, "block_ip", 2.0),
        ({**S,"packet_rate":500,"cpu_usage":50,"bandwidth_usage":60,
          "attack_type":"dns_amplification","connection_count":100,
          "flow_duration":0.05,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":6.0}, "block_ip", 2.0),
        ({**S,"packet_rate":100,"cpu_usage":20,"bandwidth_usage":15,
          "attack_type":"dns_dga","connection_count":20,
          "flow_duration":0.5,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":5.8}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":10,"bandwidth_usage":5,
          "attack_type":"ssh_brute_force","connection_count":30,
          "flow_duration":0.3,"unique_ports":1,"syn_ack_ratio":0.9,
          "payload_entropy":3.0}, "block_ip", 2.0),
        ({**S,"packet_rate":40,"cpu_usage":10,"bandwidth_usage":5,
          "attack_type":"rdp_brute_force","connection_count":25,
          "flow_duration":0.4,"unique_ports":1,"syn_ack_ratio":0.9,
          "payload_entropy":3.2}, "block_ip", 2.0),
        ({**S,"packet_rate":30,"cpu_usage":10,"bandwidth_usage":5,
          "attack_type":"ftp_brute_force","connection_count":20,
          "flow_duration":0.5,"unique_ports":1,"syn_ack_ratio":0.9,
          "payload_entropy":2.8}, "block_ip", 2.0),
        ({**S,"packet_rate":200,"cpu_usage":30,"bandwidth_usage":80,
          "attack_type":"data_exfiltration","connection_count":5,
          "flow_duration":120.0,"unique_ports":3,"syn_ack_ratio":0.99,
          "payload_entropy":7.8}, "block_ip", 2.0),
        ({**S,"packet_rate":100,"cpu_usage":25,"bandwidth_usage":30,
          "attack_type":"craft_attack","connection_count":50,
          "flow_duration":0.1,"unique_ports":50,"syn_ack_ratio":0.05,
          "payload_entropy":0.5}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"land_attack","connection_count":1,
          "flow_duration":0.0,"unique_ports":1,"syn_ack_ratio":0.0,
          "payload_entropy":0.0}, "block_ip", 2.0),
        ({**S,"packet_rate":300,"cpu_usage":40,"bandwidth_usage":50,
          "attack_type":"anomaly","connection_count":50,
          "flow_duration":5.0,"unique_ports":20,"syn_ack_ratio":0.5,
          "payload_entropy":5.0}, "raise_alert", 1.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":20,
          "attack_type":"none"}, "do_nothing", 0.5),
        ({**S,"packet_rate":80,"cpu_usage":25,"bandwidth_usage":30,
          "attack_type":"none","connection_count":8,"flow_duration":5.0,
          "unique_ports":5,"syn_ack_ratio":0.92,
          "payload_entropy":4.0}, "do_nothing", 0.5),
        ({**S,"packet_rate":120,"cpu_usage":35,"bandwidth_usage":40,
          "attack_type":"none","connection_count":15,"flow_duration":8.0,
          "unique_ports":8,"syn_ack_ratio":0.90,
          "payload_entropy":4.2}, "do_nothing", 0.5),
    ]
    stable = {
        "packet_rate":50,"cpu_usage":20,"bandwidth_usage":20,
        "attack_type":"none","connection_count":5,"flow_duration":2.0,
        "unique_ports":3,"syn_ack_ratio":0.95,"payload_entropy":3.5,
    }
    n = len(scenarios)
    for i in range(rounds):
        state, correct, reward = scenarios[i % n]
        actions  = agents_.act(state)
        final    = agents_.coordinate(actions, state=state)
        actual_r = reward if final == correct else -1.0
        agents_.learn(state, final, actual_r, next_state=stable,
                      attack_type=state["attack_type"])

@asynccontextmanager
async def lifespan(app: FastAPI):
    import glob
    if not glob.glob(os.path.join(QTABLE_DIR, "*.pt")):
        _silent_pretrain(agents, rounds=500)
    yield
    print("[MACDS] Graceful shutdown — flushing Q-tables...")
    agents.save_all(QTABLE_DIR)
    print("[MACDS] Q-tables flushed.")

app = FastAPI(title="MACDS Control Plane API", lifespan=lifespan)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

Instrumentator().instrument(app).expose(app)

@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        key = request.headers.get("X-MACDS-Key", "")
        if key != MACDS_API_KEY:
            return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    return await call_next(request)

class AttackLog(BaseModel):
    timestamp:        float
    attack_type:      str
    source_ip:        str
    packet_rate:      float = Field(default=500.0)
    cpu_usage:        float = Field(default=80.0)
    bandwidth_usage:  float = Field(default=90.0)
    confidence:       str   = Field(default="MEDIUM")
    detail:           str   = Field(default="")
    connection_count: float = Field(default=5.0)
    flow_duration:    float = Field(default=2.0)
    unique_ports:     float = Field(default=3.0)
    syn_ack_ratio:    float = Field(default=0.95)
    payload_entropy:  float = Field(default=3.5)

class FedPayload(BaseModel):
    state_dict_b64: str

_verdicts = []
_vlock = threading.Lock()

@app.get("/health")
async def health():
    return {"status": "ok", "mode": "DPI"}

@app.post("/api/logs")
@limiter.limit("200/minute")
async def receive_log(request: Request, log: AttackLog):
    try:
        ipaddress.ip_address(log.source_ip)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Invalid source_ip"})

    dedup_key = (log.source_ip, log.attack_type.lower())
    now = time.time()
    if dedup_key in _dedup_cache:
        ts, last_action = _dedup_cache[dedup_key]
        if now - ts < DEDUP_TTL:
            return {"status": "deduplicated", "action_decided": last_action, "confidence": log.confidence}
    _dedup_cache[dedup_key] = (now, None)

    packets_inspected.inc()

    current_state = {
        "packet_rate":      log.packet_rate,
        "cpu_usage":        log.cpu_usage,
        "bandwidth_usage":  log.bandwidth_usage,
        "attack_type":      log.attack_type.lower(),
        "connection_count": log.connection_count,
        "flow_duration":    log.flow_duration,
        "unique_ports":     log.unique_ports,
        "syn_ack_ratio":    log.syn_ack_ratio,
        "payload_entropy":  log.payload_entropy,
    }
    agent_actions_res = {}
    
    if log.attack_type.lower() in ("none", ""):
        attacked_state = _last_attack_state.get(log.source_ip)
        if not attacked_state:
            attacked_state = {
                "packet_rate": 500, "cpu_usage": 80,
                "bandwidth_usage": 90, "attack_type": "syn_flood",
                "connection_count": 500, "flow_duration": 0.1,
                "unique_ports": 1, "syn_ack_ratio": 0.02,
                "payload_entropy": 1.0,
            }
        
        final_action = "do_nothing"
        reward = +1.0

        if log.source_ip in _block_timestamps:
            elapsed = time.time() - _block_timestamps.pop(log.source_ip)
            if elapsed < 5.0:
                final_action = "block_ip"
                reward = -2.0
                
        agents.learn(attacked_state, final_action, reward=reward, next_state=current_state,
                     attack_type=log.attack_type, confidence=log.confidence)
        
        if log.source_ip in _last_attack_state:
            del _last_attack_state[log.source_ip]
            
        push_action(log.source_ip, "unblock_ip")
        final_action = "unblock_ip"
    else:
        _last_attack_state[log.source_ip] = current_state
        stable_state = {
            "packet_rate": 50,  "cpu_usage": 20,
            "bandwidth_usage": 20, "attack_type": "none",
            "connection_count": 5, "flow_duration": 2.0,
            "unique_ports": 3,  "syn_ack_ratio": 0.95,
            "payload_entropy": 3.5,
        }

        agent_actions = agents.act(current_state)
        agent_actions_res = agent_actions
        final_action = agents.coordinate(agent_actions, state=current_state)

        original_action = final_action

        if log.confidence.upper() == "HIGH" and log.attack_type.upper() in BLOCK_ON_SIGHT and original_action == "do_nothing":
            final_action = "block_ip"
            agent_overrides.inc()

        if final_action == "block_ip":
            reward = 2.0
        elif final_action == "raise_alert":
            reward = 0.5
        else:
            reward = -2.0

        agents.learn(current_state, final_action, reward, next_state=stable_state,
                     attack_type=log.attack_type, confidence=log.confidence, votes=agent_actions_res)

        if _dynamo_ok:
            try:
                table.put_item(Item={
                    "timestamp": Decimal(str(log.timestamp)),
                    "attack_type": log.attack_type,
                    "source_ip": log.source_ip,
                    "action_decided": final_action,
                    "packet_rate": str(log.packet_rate),
                    "confidence": log.confidence,
                    "detail": log.detail[:500]
                })
            except Exception as e:
                print(f"[DynamoDB ERROR] {e}")

        if final_action != "do_nothing":
            if final_action == "block_ip":
                _block_timestamps[log.source_ip] = time.time()
                blocks_total.inc()
            push_action(log.source_ip, final_action)

    with _vlock:
        _verdicts.append({
            "timestamp": log.timestamp,
            "attack_type": log.attack_type,
            "source_ip": log.source_ip,
            "confidence": log.confidence,
            "detail": log.detail[:200],
            "action": final_action
        })
        if len(_verdicts) > 500:
            _verdicts.pop(0)

    for name, agent in agents.agents.items():
        agent_epsilon.labels(agent=name).set(agent.epsilon)

    _dedup_cache[dedup_key] = (now, final_action)

    resp = {"status": "success", "action_decided": final_action, "confidence": log.confidence}
    if agent_actions_res:
        resp["agents_voted"] = agent_actions_res
    return resp

@app.get("/api/action")
async def get_action():
    target_ip, action = pop_action()
    if target_ip and action:
        return {"action": action, "target_ip": target_ip}
    return {"action": "none", "target_ip": ""}

@app.get("/api/verdicts")
async def get_verdicts(limit: int = Query(default=50, ge=1, le=500)):
    with _vlock:
        items = list(_verdicts)[-limit:]
    return {"verdicts": list(reversed(items)), "total": len(items)}

@app.post("/api/train")
async def train_agents(rounds: int = Query(default=500, ge=1, le=5000)):
    S = {"connection_count":5,"flow_duration":2.0,
         "unique_ports":3,"syn_ack_ratio":0.95,"payload_entropy":3.5}
    scenarios = [
        ({**S,"packet_rate":3000,"cpu_usage":95,"bandwidth_usage":99,
          "attack_type":"syn_flood","connection_count":5000,
          "flow_duration":0.1,"unique_ports":1,"syn_ack_ratio":0.02,
          "payload_entropy":1.0}, "block_ip", 2.0),
        ({**S,"packet_rate":2500,"cpu_usage":85,"bandwidth_usage":95,
          "attack_type":"udp_flood","connection_count":3000,
          "flow_duration":0.05,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":7.5}, "block_ip", 2.0),
        ({**S,"packet_rate":2000,"cpu_usage":80,"bandwidth_usage":90,
          "attack_type":"icmp_flood","connection_count":2000,
          "flow_duration":0.01,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":0.5}, "block_ip", 2.0),
        ({**S,"packet_rate":1500,"cpu_usage":75,"bandwidth_usage":85,
          "attack_type":"http_flood","connection_count":1500,
          "flow_duration":0.3,"unique_ports":1,"syn_ack_ratio":0.5,
          "payload_entropy":4.5}, "block_ip", 2.0),
        ({**S,"packet_rate":200,"cpu_usage":30,"bandwidth_usage":20,
          "attack_type":"port_scan","connection_count":200,
          "flow_duration":0.1,"unique_ports":500,"syn_ack_ratio":0.1,
          "payload_entropy":0.0}, "raise_alert", 1.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"sql_injection","connection_count":3,
          "flow_duration":1.5,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.2}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"xss","connection_count":3,"flow_duration":1.0,
          "unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.0}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"path_traversal","connection_count":2,
          "flow_duration":0.8,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":3.8}, "block_ip", 2.0),
        ({**S,"packet_rate":20,"cpu_usage":15,"bandwidth_usage":5,
          "attack_type":"log4shell","connection_count":1,
          "flow_duration":0.5,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":5.5}, "block_ip", 2.0),
        ({**S,"packet_rate":20,"cpu_usage":15,"bandwidth_usage":5,
          "attack_type":"shellshock","connection_count":1,
          "flow_duration":0.3,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.8}, "block_ip", 2.0),
        ({**S,"packet_rate":20,"cpu_usage":15,"bandwidth_usage":5,
          "attack_type":"cmd_injection","connection_count":1,
          "flow_duration":0.4,"unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.5}, "block_ip", 2.0),
        ({**S,"packet_rate":30,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"ssrf","connection_count":2,"flow_duration":1.0,
          "unique_ports":1,"syn_ack_ratio":0.99,
          "payload_entropy":4.3}, "block_ip", 2.0),
        ({**S,"packet_rate":500,"cpu_usage":50,"bandwidth_usage":60,
          "attack_type":"dns_amplification","connection_count":100,
          "flow_duration":0.05,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":6.0}, "block_ip", 2.0),
        ({**S,"packet_rate":100,"cpu_usage":20,"bandwidth_usage":15,
          "attack_type":"dns_dga","connection_count":20,
          "flow_duration":0.5,"unique_ports":1,"syn_ack_ratio":1.0,
          "payload_entropy":5.8}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":10,"bandwidth_usage":5,
          "attack_type":"ssh_brute_force","connection_count":30,
          "flow_duration":0.3,"unique_ports":1,"syn_ack_ratio":0.9,
          "payload_entropy":3.0}, "block_ip", 2.0),
        ({**S,"packet_rate":40,"cpu_usage":10,"bandwidth_usage":5,
          "attack_type":"rdp_brute_force","connection_count":25,
          "flow_duration":0.4,"unique_ports":1,"syn_ack_ratio":0.9,
          "payload_entropy":3.2}, "block_ip", 2.0),
        ({**S,"packet_rate":30,"cpu_usage":10,"bandwidth_usage":5,
          "attack_type":"ftp_brute_force","connection_count":20,
          "flow_duration":0.5,"unique_ports":1,"syn_ack_ratio":0.9,
          "payload_entropy":2.8}, "block_ip", 2.0),
        ({**S,"packet_rate":200,"cpu_usage":30,"bandwidth_usage":80,
          "attack_type":"data_exfiltration","connection_count":5,
          "flow_duration":120.0,"unique_ports":3,"syn_ack_ratio":0.99,
          "payload_entropy":7.8}, "block_ip", 2.0),
        ({**S,"packet_rate":100,"cpu_usage":25,"bandwidth_usage":30,
          "attack_type":"craft_attack","connection_count":50,
          "flow_duration":0.1,"unique_ports":50,"syn_ack_ratio":0.05,
          "payload_entropy":0.5}, "block_ip", 2.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":10,
          "attack_type":"land_attack","connection_count":1,
          "flow_duration":0.0,"unique_ports":1,"syn_ack_ratio":0.0,
          "payload_entropy":0.0}, "block_ip", 2.0),
        ({**S,"packet_rate":300,"cpu_usage":40,"bandwidth_usage":50,
          "attack_type":"anomaly","connection_count":50,
          "flow_duration":5.0,"unique_ports":20,"syn_ack_ratio":0.5,
          "payload_entropy":5.0}, "raise_alert", 1.0),
        ({**S,"packet_rate":50,"cpu_usage":20,"bandwidth_usage":20,
          "attack_type":"none"}, "do_nothing", 0.5),
        ({**S,"packet_rate":80,"cpu_usage":25,"bandwidth_usage":30,
          "attack_type":"none","connection_count":8,"flow_duration":5.0,
          "unique_ports":5,"syn_ack_ratio":0.92,
          "payload_entropy":4.0}, "do_nothing", 0.5),
        ({**S,"packet_rate":120,"cpu_usage":35,"bandwidth_usage":40,
          "attack_type":"none","connection_count":15,"flow_duration":8.0,
          "unique_ports":8,"syn_ack_ratio":0.90,
          "payload_entropy":4.2}, "do_nothing", 0.5),
    ]
    stable_state = {
        "packet_rate":50,"cpu_usage":20,"bandwidth_usage":20,
        "attack_type":"none","connection_count":5,"flow_duration":2.0,
        "unique_ports":3,"syn_ack_ratio":0.95,"payload_entropy":3.5,
    }
    block_count = 0
    scen_ct = len(scenarios)
    for i in range(rounds):
        state, correct, reward = scenarios[i % scen_ct]
        actions = agents.act(state)
        final = agents.coordinate(actions, state=state)
        actual_reward = reward if final == correct else -1.0
        agents.learn(state, final, actual_reward, next_state=stable_state,
                     attack_type=state["attack_type"])
        if final == "block_ip":
            block_count += 1

    agents.save_all(QTABLE_DIR)

    return {
        "rounds": rounds,
        "block_ip_count": block_count,
        "block_ip_rate": f"{block_count / rounds * 100:.1f}%",
        "message": f"Agents trained in-process. Q-tables saved to {QTABLE_DIR}/",
    }

@app.post("/api/federate")
async def post_federate(payload: FedPayload):
    return handle_federation(payload.state_dict_b64)

@app.get("/api/status")
async def status():
    for name, agent in agents.agents.items():
        agent_epsilon.labels(agent=name).set(agent.epsilon)
        
    if REDIS_OK:
        pending = _redis.hgetall("macds:pending")
    else:
        pending = dict(pending_actions)
        
    return {
        "pending_actions": pending,
        "agent_epsilons": {
            name: round(agent.epsilon, 4)
            for name, agent in agents.agents.items()
        },
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
