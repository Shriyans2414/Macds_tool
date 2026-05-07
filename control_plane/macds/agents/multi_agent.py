"""
MACDS Multi-Agent System — Peak Version

Upgrades vs previous version:
  1. Dueling QNetwork: Value stream + Advantage stream instead of
     flat MLP. Q(s,a) = V(s) + A(s,a) - mean(A). Faster convergence
     on states where most actions have similar value (normal traffic).
  2. Double DQN: online net selects action, target net evaluates.
     Eliminates Q-value overestimation that caused over-blocking.
  3. Prioritised Experience Replay: samples by |TD-error|^alpha.
     Rare attacks (log4shell, shellshock, brute force) are replayed
     proportionally instead of being drowned by benign traffic.
  4. Gradient clipping: prevents exploding gradients on large rewards.
  5. State dim 35 = 8 continuous + 27-type one-hot (was 21 = 3 + 18).
     New continuous features: connection_count, flow_duration,
     unique_ports, syn_ack_ratio, payload_entropy.
     New attack types: ssh_brute_force, rdp_brute_force,
     ftp_brute_force, data_exfiltration.
  6. Confidence-weighted coordination: each agent vote weighted by
     Q-gap (top2 Q-value difference). Certain agents outweigh
     uncertain ones. Safety override: any agent with Q-gap >= 0.65
     voting block_ip triggers immediate block.
  7. Richer per-agent reward shaping covering all new attack types.
"""

import os
import random
from collections import deque

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

ATTACK_TYPES = [
    "none",
    "syn_flood", "udp_flood", "icmp_flood", "http_flood",
    "port_scan", "land_attack",
    "sql_injection", "xss", "path_traversal",
    "log4shell", "shellshock", "cmd_injection", "ssrf",
    "spring4shell", "struts_rce", "php_injection", "xxe", "ssti",
    "dns_amplification", "dns_dga",
    "ssh_brute_force", "rdp_brute_force", "ftp_brute_force",
    "craft_attack", "anomaly", "data_exfiltration",
]

ATTACK_INDEX   = {a: i for i, a in enumerate(ATTACK_TYPES)}
N_ATTACK_TYPES = len(ATTACK_TYPES)   # 27
CONTINUOUS_DIM = 8
STATE_DIM      = CONTINUOUS_DIM + N_ATTACK_TYPES  # 35

ACTIONS   = ["do_nothing", "raise_alert", "block_ip", "unblock_ip"]
N_ACTIONS = len(ACTIONS)

QTABLE_DIR = os.environ.get("QTABLE_DIR", "/app/qtables")


class DuelingQNetwork(nn.Module):
    def __init__(self, hidden: int = 128):
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(STATE_DIM, hidden), nn.LayerNorm(hidden), nn.ReLU(),
            nn.Linear(hidden, hidden),   nn.LayerNorm(hidden), nn.ReLU(),
        )
        self.value_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(), nn.Linear(64, 1)
        )
        self.adv_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(), nn.Linear(64, N_ACTIONS)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        f   = self.shared(x)
        v   = self.value_head(f)
        adv = self.adv_head(f)
        return v + (adv - adv.mean(dim=1, keepdim=True))


class PrioritisedReplayBuffer:
    def __init__(self, capacity: int = 50_000, alpha: float = 0.6):
        self.capacity   = capacity
        self.alpha      = alpha
        self.buf: list  = []
        self.priorities = np.zeros(capacity, dtype=np.float32)
        self.pos        = 0
        self._max_pri   = 1.0

    def push(self, s, a, r, s2, done: bool = False):
        if len(self.buf) < self.capacity:
            self.buf.append(None)
        self.buf[self.pos]        = (s, a, r, s2, done)
        self.priorities[self.pos] = self._max_pri
        self.pos = (self.pos + 1) % self.capacity

    def sample(self, batch: int, beta: float = 0.4):
        n     = len(self.buf)
        probs = self.priorities[:n] ** self.alpha
        probs /= probs.sum()
        idxs  = np.random.choice(n, batch, replace=False, p=probs)
        items = [self.buf[i] for i in idxs]
        w     = (n * probs[idxs]) ** (-beta)
        w    /= w.max()
        s, a, r, s2, d = zip(*items)
        return (
            np.array(s,  dtype=np.float32),
            np.array(a),
            np.array(r,  dtype=np.float32),
            np.array(s2, dtype=np.float32),
            np.array(d,  dtype=np.float32),
            idxs,
            torch.tensor(w, dtype=torch.float32),
        )

    def update_priorities(self, idxs, td_errors):
        for i, e in zip(idxs, td_errors):
            p = float(abs(e) + 1e-6)
            self.priorities[i] = p
            self._max_pri = max(self._max_pri, p)

    def __len__(self):
        return len(self.buf)


class DQNAgent:
    def __init__(
        self,
        name:               str,
        alpha:              float = 3e-4,
        gamma:              float = 0.95,
        epsilon:            float = 0.25,
        epsilon_min:        float = 0.01,
        epsilon_decay:      float = 0.9997,
        batch_size:         int   = 64,
        target_update_freq: int   = 300,
        hidden:             int   = 128,
        beta_start:         float = 0.4,
        beta_end:           float = 1.0,
        beta_steps:         int   = 100_000,
    ):
        self.name               = name
        self.actions            = ACTIONS
        self.gamma              = gamma
        self.epsilon            = epsilon
        self.epsilon_min        = epsilon_min
        self.epsilon_decay      = epsilon_decay
        self.batch_size         = batch_size
        self.target_update_freq = target_update_freq
        self._steps             = 0
        self._beta_start        = beta_start
        self._beta_end          = beta_end
        self._beta_steps        = beta_steps

        self.device     = torch.device("cpu")
        self.online_net = DuelingQNetwork(hidden).to(self.device)
        self.target_net = DuelingQNetwork(hidden).to(self.device)
        self.target_net.load_state_dict(self.online_net.state_dict())
        self.target_net.eval()

        self.optimizer = torch.optim.Adam(
            self.online_net.parameters(), lr=alpha, eps=1e-8
        )
        self.replay = PrioritisedReplayBuffer()

    @property
    def _beta(self) -> float:
        frac = min(1.0, self._steps / self._beta_steps)
        return self._beta_start + frac * (self._beta_end - self._beta_start)

    def _encode_state(self, state: dict) -> np.ndarray:
        pr  = min(state.get("packet_rate",      0) / 5000.0,  1.0)
        cpu = min(state.get("cpu_usage",         0) / 100.0,   1.0)
        bw  = min(state.get("bandwidth_usage",   0) / 100.0,   1.0)
        cc  = min(state.get("connection_count",  0) / 10000.0, 1.0)
        fd  = min(state.get("flow_duration",     0) / 300.0,   1.0)
        up  = min(state.get("unique_ports",      0) / 65535.0, 1.0)
        sar = float(np.clip(state.get("syn_ack_ratio",   1.0), 0.0, 1.0))
        pe  = float(np.clip(state.get("payload_entropy", 0.0) / 8.0, 0.0, 1.0))

        onehot = np.zeros(N_ATTACK_TYPES, dtype=np.float32)
        onehot[ATTACK_INDEX.get(
            state.get("attack_type", "none").lower(), 0
        )] = 1.0

        return np.concatenate([
            np.array([pr, cpu, bw, cc, fd, up, sar, pe], dtype=np.float32),
            onehot,
        ])

    def select_action(self, state: dict) -> str:
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        s = torch.tensor(
            self._encode_state(state)
        ).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q = self.online_net(s)
        return self.actions[q.argmax(dim=1).item()]

    def q_values(self, state: dict) -> torch.Tensor:
        s = torch.tensor(
            self._encode_state(state)
        ).unsqueeze(0).to(self.device)
        with torch.no_grad():
            return self.online_net(s).squeeze(0)

    def update(self, state: dict, action: str, reward: float,
               next_state: dict, done: bool = False):
        s  = self._encode_state(state)
        s2 = self._encode_state(next_state)
        self.replay.push(s, self.actions.index(action), reward, s2, done)

        if len(self.replay) < self.batch_size:
            return

        st, at, rt, s2t, dt, idxs, wt = self.replay.sample(
            self.batch_size, beta=self._beta
        )
        st  = torch.tensor(st).to(self.device)
        at  = torch.tensor(at, dtype=torch.long).to(self.device)
        rt  = torch.tensor(rt).to(self.device)
        s2t = torch.tensor(s2t).to(self.device)
        dt  = torch.tensor(dt).to(self.device)
        wt  = wt.to(self.device)

        q_vals = self.online_net(st).gather(1, at.unsqueeze(1)).squeeze(1)

        with torch.no_grad():
            next_acts = self.online_net(s2t).argmax(dim=1, keepdim=True)
            next_q    = self.target_net(s2t).gather(1, next_acts).squeeze(1)
            targets   = rt + self.gamma * next_q * (1.0 - dt)

        td_errors = (q_vals - targets).detach().cpu().numpy()
        loss = (wt * F.mse_loss(q_vals, targets, reduction="none")).mean()

        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(
            self.online_net.parameters(), max_norm=10.0
        )
        self.optimizer.step()

        self.replay.update_priorities(idxs, td_errors)
        self._steps += 1

        if self._steps % 10 == 0:
            self.epsilon = max(
                self.epsilon_min, self.epsilon * self.epsilon_decay
            )
        if self._steps % self.target_update_freq == 0:
            self.target_net.load_state_dict(self.online_net.state_dict())

    def save(self, path: str):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        torch.save({
            "online":  self.online_net.state_dict(),
            "target":  self.target_net.state_dict(),
            "epsilon": self.epsilon,
            "steps":   self._steps,
        }, path)

    def load(self, path: str):
        if not os.path.exists(path):
            return
        ckpt = torch.load(path, map_location="cpu", weights_only=True)
        self.online_net.load_state_dict(ckpt["online"])
        self.target_net.load_state_dict(ckpt["target"])
        self.epsilon = ckpt.get("epsilon", self.epsilon)
        self._steps  = ckpt.get("steps",   0)


class MultiAgentSystem:
    def __init__(self):
        self._update_count = 0
        self.agents = {
            "traffic_agent": DQNAgent(
                "traffic_agent",
                alpha=5e-4, epsilon=0.3,  epsilon_decay=0.9995,
                hidden=128, target_update_freq=200,
            ),
            "ids_agent": DQNAgent(
                "ids_agent",
                alpha=2e-4, epsilon=0.15, epsilon_decay=0.9998,
                hidden=128, target_update_freq=300,
            ),
            "response_agent": DQNAgent(
                "response_agent",
                alpha=8e-4, epsilon=0.10, epsilon_decay=0.9997,
                hidden=64,  target_update_freq=150,
            ),
        }
        self.load_all(QTABLE_DIR)

    def act(self, state: dict) -> dict:
        return {n: a.select_action(state) for n, a in self.agents.items()}

    def _confidence(self, agent: DQNAgent, state: dict) -> float:
        q = agent.q_values(state)
        top2, _ = torch.topk(q, 2)
        gap = (top2[0] - top2[1]).item()
        return float(torch.sigmoid(torch.tensor(gap)).item())

    def coordinate(self, actions: dict, state: dict = None) -> str:
        if state is not None:
            for name, agent in self.agents.items():
                if actions[name] == "block_ip":
                    if self._confidence(agent, state) >= 0.65:
                        return "block_ip"
            scores: dict = {a: 0.0 for a in ACTIONS}
            for name, agent in self.agents.items():
                scores[actions[name]] += self._confidence(agent, state)
            return max(scores, key=scores.get)

        vals = list(actions.values())
        if "block_ip"   in vals:          return "block_ip"
        if vals.count("unblock_ip") >= 2: return "unblock_ip"
        if "raise_alert" in vals:         return "raise_alert"
        return "do_nothing"

    def learn(
        self,
        state:       dict,
        action:      str,
        reward:      float,
        next_state:  dict,
        attack_type: str  = "unknown",
        confidence:  str  = "MEDIUM",
        votes:       dict = None,
    ):
        conf_mult = {"HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5}.get(
            confidence.upper(), 1.0
        )
        is_volumetric = attack_type.lower() in (
            "syn_flood", "udp_flood", "icmp_flood", "http_flood"
        )
        is_app = attack_type.lower() in (
            "sql_injection", "xss", "log4shell", "shellshock",
            "cmd_injection", "ssrf", "path_traversal", "data_exfiltration",
            "spring4shell", "struts_rce", "php_injection", "xxe", "ssti",
        )
        is_brute = attack_type.lower() in (
            "ssh_brute_force", "rdp_brute_force", "ftp_brute_force"
        )

        for name, agent in self.agents.items():
            ia = votes[name] if votes and name in votes else action

            if name == "traffic_agent":
                adj = reward
                if ia == "do_nothing" and is_volumetric:               adj -= 3.0
                if ia == "block_ip"   and attack_type.lower() == "none": adj -= 2.0

            elif name == "ids_agent":
                adj = reward
                if ia == "block_ip"   and attack_type.lower() == "none": adj -= 2.0
                if ia == "do_nothing" and is_app:                        adj -= 1.5
                if ia == "do_nothing" and is_brute:                      adj -= 1.0

            elif name == "response_agent":
                adj = reward * conf_mult
                if ia == "raise_alert" and confidence.upper() == "LOW":  adj += 1.0
                if ia == "block_ip"    and confidence.upper() == "LOW":  adj -= 1.5

            else:
                adj = reward

            agent.update(state, ia, adj, next_state)

        self._update_count += 1
        if self._update_count % 50 == 0:
            self.save_all(QTABLE_DIR)

    def save_all(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        for name, agent in self.agents.items():
            agent.save(os.path.join(directory, f"{name}.pt"))

    def load_all(self, directory: str):
        for name, agent in self.agents.items():
            agent.load(os.path.join(directory, f"{name}.pt"))
