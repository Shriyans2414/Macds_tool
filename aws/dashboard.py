"""
MACDS Live Dashboard
Real-time security monitoring dashboard.
Run: python3 aws/dashboard.py
Access: http://YOUR_SERVER_IP:9000
"""

import http.server
import json
import os
import threading
import time
import urllib.request
from html import escape
from collections import Counter, deque

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:8000")
MACDS_API_KEY     = os.environ.get("MACDS_API_KEY", "changeme-set-in-env")
DASHBOARD_PORT    = int(os.environ.get("DASHBOARD_PORT", "9000"))
DPI_LOG           = os.environ.get("DPI_LOG", "logs/dpi_events.csv")

# Cache for verdicts data
_cache = {"data": None, "ts": 0}
_cache_lock = threading.Lock()
CACHE_TTL = 5  # seconds

def fetch_verdicts():
    now = time.time()
    with _cache_lock:
        if _cache["data"] and now - _cache["ts"] < CACHE_TTL:
            return _cache["data"]
    try:
        req = urllib.request.Request(
            f"{CONTROL_PLANE_URL}/api/verdicts?limit=500",
            headers={"X-MACDS-Key": MACDS_API_KEY}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read())
        with _cache_lock:
            _cache["data"] = data
            _cache["ts"]   = now
        return data
    except Exception:
        return {"verdicts": [], "total": 0}

def read_dpi_stats():
    stats = {
        "unique_ips": 0,
        "total_detections": 0,
        "confirmed_attacks": 0,
        "attack_types": {},
        "recent": [],
    }
    try:
        lines = open(DPI_LOG).readlines()
        ips   = set()
        types = Counter()
        confirmed = 0
        recent = []
        for line in lines[1:]:
            parts = line.strip().split(",", 5)
            if len(parts) < 4: continue
            ts, event, atype, src = parts[0], parts[1], parts[2], parts[3]
            ips.add(src)
            if event == "ATTACK_START":
                confirmed += 1
                types[atype] += 1
            recent.append((float(ts), event, atype, src,
                           parts[4] if len(parts) > 4 else "",
                           parts[5] if len(parts) > 5 else ""))
        stats["unique_ips"]       = len(ips)
        stats["total_detections"] = len(lines) - 1
        stats["confirmed_attacks"]= confirmed
        stats["attack_types"]     = dict(types.most_common(10))
        stats["recent"]           = recent[-50:]
    except Exception:
        pass
    return stats

def render_dashboard():
    stats   = read_dpi_stats()
    verdict = fetch_verdicts()

    actions = Counter(v["action"] for v in verdict["verdicts"])
    blocked = actions.get("block_ip", 0)
    alerted = actions.get("raise_alert", 0)

    # Attack type bars
    type_bars = ""
    max_count = max(stats["attack_types"].values(), default=1)
    colors = {
        "CRAFT_ATTACK": "#f85149",
        "SSH_BRUTE_FORCE": "#ff7b72",
        "CMD_INJECTION": "#ffa657",
        "DNS_AMPLIFICATION": "#d2a8ff",
        "SYN_FLOOD": "#79c0ff",
        "PATH_TRAVERSAL": "#56d364",
        "HTTP_FLOOD": "#e3b341",
        "PORT_SCAN": "#bc8cff",
    }
    for atype, count in sorted(stats["attack_types"].items(),
                                key=lambda x: -x[1]):
        pct   = int(count / max_count * 100)
        color = colors.get(atype, "#8b949e")
        type_bars += f"""
        <div class="bar-row">
          <span class="bar-label">{escape(atype)}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{color}"></div>
          </div>
          <span class="bar-count">{count}</span>
        </div>"""

    # Recent events table
    rows = ""
    for ts, event, atype, src, detail, conf in reversed(stats["recent"][-20:]):
        t = time.strftime("%H:%M:%S", time.gmtime(float(ts)))
        color = ("#f85149" if event == "ATTACK_START"
                 else "#e3b341" if event == "SUSPICIOUS"
                 else "#56d364")
        rows += f"""<tr>
          <td style="color:#8b949e">{t}</td>
          <td style="color:{color}">{escape(event)}</td>
          <td style="color:#ffa657">{escape(atype)}</td>
          <td style="color:#79c0ff">{escape(src)}</td>
          <td style="color:#8b949e;max-width:300px;overflow:hidden;text-overflow:ellipsis">
            {escape(str(detail)[:80])}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
  <title>MACDS — Live Security Dashboard</title>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="10">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;padding:20px}}
    h1{{color:#58a6ff;font-size:1.4rem;margin-bottom:4px}}
    .subtitle{{color:#8b949e;font-size:.85rem;margin-bottom:24px}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}}
    .card-value{{font-size:2.2rem;font-weight:700;margin-bottom:4px}}
    .card-label{{color:#8b949e;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}}
    .red{{color:#f85149}}.green{{color:#56d364}}.blue{{color:#79c0ff}}
    .yellow{{color:#e3b341}}.purple{{color:#d2a8ff}}
    .section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}}
    .section h2{{color:#58a6ff;font-size:1rem;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #30363d}}
    .bar-row{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
    .bar-label{{width:180px;font-size:.82rem;color:#c9d1d9;text-align:right;flex-shrink:0}}
    .bar-track{{flex:1;background:#21262d;border-radius:4px;height:18px;overflow:hidden}}
    .bar-fill{{height:100%;border-radius:4px;transition:width .3s}}
    .bar-count{{width:50px;text-align:right;font-size:.82rem;color:#8b949e}}
    table{{width:100%;border-collapse:collapse;font-size:.82rem}}
    th{{color:#8b949e;text-align:left;padding:8px 12px;border-bottom:1px solid #30363d;font-weight:500}}
    td{{padding:7px 12px;border-bottom:1px solid #21262d}}
    tr:hover td{{background:#1c2128}}
    .pulse{{animation:pulse 2s infinite}}
    @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
    .live-dot{{display:inline-block;width:8px;height:8px;background:#56d364;border-radius:50%;margin-right:6px}}
  </style>
</head>
<body>
  <h1>⚡ MACDS — Multi-Agent Cyber Defence System</h1>
  <p class="subtitle">
    <span class="live-dot pulse"></span>
    Live dashboard — auto-refreshes every 10 seconds &nbsp;|&nbsp;
    {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
  </p>

  <div class="grid">
    <div class="card">
      <div class="card-value red">{stats["unique_ips"]:,}</div>
      <div class="card-label">Unique Attackers</div>
    </div>
    <div class="card">
      <div class="card-value blue">{stats["total_detections"]:,}</div>
      <div class="card-label">Total Detections</div>
    </div>
    <div class="card">
      <div class="card-value red">{stats["confirmed_attacks"]:,}</div>
      <div class="card-label">Confirmed Attacks</div>
    </div>
    <div class="card">
      <div class="card-value green">{blocked:,}</div>
      <div class="card-label">IPs Blocked</div>
    </div>
    <div class="card">
      <div class="card-value yellow">{alerted:,}</div>
      <div class="card-label">Alerts Raised</div>
    </div>
    <div class="card">
      <div class="card-value purple">{len(stats["attack_types"])}</div>
      <div class="card-label">Attack Categories</div>
    </div>
  </div>

  <div class="section">
    <h2>Attack Type Breakdown</h2>
    {type_bars if type_bars else '<p style="color:#8b949e">No attacks detected yet</p>'}
  </div>

  <div class="section">
    <h2>Live Event Feed (last 20)</h2>
    <table>
      <thead>
        <tr>
          <th>Time</th><th>Event</th><th>Type</th>
          <th>Source IP</th><th>Detail</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        html = render_dashboard().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", DASHBOARD_PORT), Handler)
    print(f"[*] MACDS Dashboard running at http://0.0.0.0:{DASHBOARD_PORT}")
    print(f"[*] Control plane: {CONTROL_PLANE_URL}")
    print(f"[*] DPI log: {DPI_LOG}")
    server.serve_forever()
