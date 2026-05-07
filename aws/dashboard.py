from html import escape
import os
import requests
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:8000")
MACDS_API_KEY = os.environ.get("MACDS_API_KEY", "changeme-set-in-env")

_cached_verdicts = []
_last_fetch = 0.0

def fetch_verdicts(limit=200):
    global _cached_verdicts, _last_fetch
    now = time.time()
    if now - _last_fetch < 5.0:
        return _cached_verdicts
        
    try:
        resp = requests.get(
            f"{CONTROL_PLANE_URL}/api/verdicts",
            headers={"X-MACDS-Key": MACDS_API_KEY},
            params={"limit": limit},
            timeout=5
        )
        if resp.status_code == 200:
            _cached_verdicts = resp.json().get("verdicts", [])
            _last_fetch = now
    except Exception as e:
        print(f"[Dashboard ERROR] {e}")
        
    return _cached_verdicts

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def do_GET(self):
        items = fetch_verdicts()
        counts = {}
        actions = {"block_ip": 0, "raise_alert": 0, "do_nothing": 0}
        for item in items:
            at = item.get("attack_type", "unknown")
            counts[at] = counts.get(at, 0) + 1
            ad = item.get("action", "do_nothing")
            if ad in actions:
                actions[ad] += 1

        rows = "".join(f'''<tr>
<td>{escape(str(i.get("attack_type","")))} </td>
<td>{escape(str(i.get("source_ip","")))} </td>
<td style="color:{"#f85149" if i.get("action")=="block_ip" else "#d29922" if i.get("action")=="raise_alert" else "#8b949e"}">{escape(str(i.get("action","")))} </td>
<td>{escape(str(i.get("packet_rate","")))} pps</td>
</tr>''' for i in items)

        breakdown = "".join(
            f'<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>'
            for k, v in counts.items()
        )

        html = f"""<!DOCTYPE html>
<html>
<head>
<title>MACDS Live Dashboard</title>
<meta http-equiv="refresh" content="5">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:monospace;background:#0d1117;color:#e6edf3;padding:30px}}
h1{{color:#58a6ff;margin-bottom:5px}}
.sub{{color:#8b949e;margin-bottom:30px;font-size:13px}}
.cards{{display:flex;gap:20px;margin-bottom:30px}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;flex:1;text-align:center}}
.card h2{{font-size:36px;margin-bottom:5px}}
.card p{{color:#8b949e;font-size:12px}}
.total{{color:#58a6ff}}.blocked{{color:#f85149}}.alerted{{color:#d29922}}
h3{{color:#3fb950;margin-bottom:15px}}
table{{border-collapse:collapse;width:100%;margin-bottom:30px;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;padding:12px 16px;text-align:left;color:#58a6ff;font-size:13px}}
td{{padding:12px 16px;border-bottom:1px solid #21262d;font-size:13px}}
</style>
</head>
<body>
<h1>MACDS Attack Monitor</h1>
<p class="sub">Live dashboard — auto-refreshes every 5 seconds (API backend)</p>
<div class="cards">
  <div class="card"><h2 class="total">{len(items)}</h2><p>Recent Attacks (200)</p></div>
  <div class="card"><h2 class="blocked">{actions["block_ip"]}</h2><p>IPs Blocked</p></div>
  <div class="card"><h2 class="alerted">{actions["raise_alert"]}</h2><p>Alerts Raised</p></div>
  <div class="card"><h2 style="color:#3fb950">{len(counts)}</h2><p>Attack Types Seen</p></div>
</div>
<h3>Attack Type Breakdown</h3>
<table><tr><th>Attack Type</th><th>Count</th></tr>{breakdown}</table>
<h3>Recent Attack History</h3>
<table>
<tr><th>Attack Type</th><th>Source IP</th><th>Action Taken</th><th>Packet Rate</th></tr>
{rows}
</table>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

print("Dashboard running on http://0.0.0.0:9000")
HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
