"""
Shared web-UI chrome (nav bar + base stylesheet) and the HTML landing page.

The demo page, the dashboard and this home page all pull `SHARED_CSS` and
`nav_html()` from here so they look like one app and link to each other -- no
one should ever have to type `/gateway/backends` or `/gateway/stats` by hand.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

GITHUB_URL = "https://github.com/HerschCode/llm-security-gateway"

SHARED_CSS = """
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #0d1117; color: #c9d1d9; margin: 0; line-height: 1.5; }
  a { color: #58a6ff; }
  .nav { position: sticky; top: 0; z-index: 10; display: flex; align-items: center; gap: 4px;
         background: #010409; border-bottom: 1px solid #21262d; padding: 10px 20px; font-size: 13px; }
  .nav .brand { font-weight: 700; color: #58a6ff; margin-right: 14px; }
  .nav a { color: #c9d1d9; text-decoration: none; padding: 5px 10px; border-radius: 6px; }
  .nav a:hover { background: #161b22; }
  .nav a.active { background: #161b22; color: #58a6ff; }
  .nav .spacer { flex: 1; }
  .nav .dot { width: 8px; height: 8px; border-radius: 50%; background: #8b949e; display: inline-block; margin-right: 6px; }
  .nav .dot.ok { background: #3fb950; } .nav .dot.bad { background: #f85149; }
  .wrap { padding: 24px; max-width: 1000px; margin: 0 auto; }
  h1 { color: #58a6ff; font-size: 20px; margin: 0 0 4px; }
  .sub { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
  @media (max-width: 720px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
  .tile { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; }
  .tile .k { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: .04em; }
  .tile .v { font-size: 22px; font-weight: 700; color: #58a6ff; margin-top: 2px; }
  .cards { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 22px; }
  @media (max-width: 720px) { .cards { grid-template-columns: 1fr; } }
  .card { display: block; text-decoration: none; background: #161b22; border: 1px solid #30363d;
          border-radius: 10px; padding: 18px; color: #c9d1d9; transition: border-color .12s; }
  .card:hover { border-color: #58a6ff; }
  .card h3 { margin: 0 0 4px; color: #58a6ff; font-size: 15px; }
  .card p { margin: 0; font-size: 12px; color: #8b949e; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 7px 12px; border-bottom: 1px solid #21262d; font-size: 12.5px; }
  th { color: #8b949e; text-transform: uppercase; font-size: 10.5px; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; border: 1px solid; }
  .pill.ok { color: #3fb950; border-color: #3fb95055; background: #3fb95015; }
  .pill.bad { color: #f85149; border-color: #f8514955; background: #f8514915; }
  .pill.mut { color: #8b949e; border-color: #30363d; }
  h2 { font-size: 13px; color: #8b949e; text-transform: uppercase; letter-spacing: .04em; margin: 22px 0 8px; }
  .foot { margin-top: 24px; font-size: 12px; color: #8b949e; }
"""


def nav_html(active: str = "") -> str:
    def cls(name): return ' class="active"' if name == active else ""
    return f"""
  <div class="nav">
    <span class="brand">LLM Security Gateway</span>
    <a href="/"{cls('home')}>Home</a>
    <a href="/gateway/demo"{cls('demo')}>Demo</a>
    <a href="/gateway/dashboard"{cls('dashboard')}>Dashboard</a>
    <span class="spacer"></span>
    <span id="nav-status"><span class="dot"></span>checking…</span>
    <a href="{GITHUB_URL}" target="_blank" rel="noopener">GitHub ↗</a>
  </div>
  <script>
    fetch('/health').then(r => r.json()).then(d => {{
      const s = document.getElementById('nav-status');
      s.innerHTML = '<span class="dot ' + (d.status === 'ok' ? 'ok' : 'bad') + '"></span>' +
        (d.status === 'ok' ? 'service up' : 'service down');
    }}).catch(() => {{
      document.getElementById('nav-status').innerHTML = '<span class="dot bad"></span>unreachable';
    }});
  </script>
"""


_HOME_HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM Security Gateway</title>
<style>{SHARED_CSS}</style>
</head><body>
{nav_html('home')}
<div class="wrap">
  <h1>LLM Security Gateway</h1>
  <div class="sub">Security middleware that sits in front of an LLM backend and inspects
    traffic both ways — prompt injection, PII leakage, jailbreak-compliance, role-based data exposure.</div>

  <div class="tiles" id="tiles">
    <div class="tile"><div class="k">Service</div><div class="v" id="t-health">…</div></div>
    <div class="tile"><div class="k">Mode</div><div class="v" id="t-mode">…</div></div>
    <div class="tile"><div class="k">Requests (5&nbsp;min)</div><div class="v" id="t-req">…</div></div>
    <div class="tile"><div class="k">Block rate</div><div class="v" id="t-block">…</div></div>
  </div>

  <div class="cards">
    <a class="card" href="/gateway/demo">
      <h3>▶ Interactive demo</h3>
      <p>Pick an attack, pick a backend, hit Run. Same prompt sent straight at the backend
         and through the gateway, side by side — verdict, which layer fired, latency.</p>
    </a>
    <a class="card" href="/gateway/dashboard">
      <h3>📊 Live dashboard</h3>
      <p>Block rate, decisions by phase, blocks by detection layer, recent events —
         from the same JSONL log every request writes, auto-refreshing.</p>
    </a>
  </div>

  <h2>Backends &amp; connectivity</h2>
  <table id="conn"><thead><tr><th>Backend</th><th>Transport</th><th>Reachable</th><th>Detail</th></tr></thead>
    <tbody><tr><td colspan="4">loading…</td></tr></tbody></table>

  <div class="foot">
    Raw JSON: <a href="/health">/health</a> ·
    <a href="/gateway/stats">/gateway/stats</a> ·
    <a href="/gateway/backends">/gateway/backends</a> ·
    <a href="/gateway/connectivity">/gateway/connectivity</a>
  </div>
</div>

<script>
async function load() {{
  try {{
    const h = await (await fetch('/health')).json();
    document.getElementById('t-health').textContent = h.status === 'ok' ? 'up' : 'down';
  }} catch {{ document.getElementById('t-health').textContent = '—'; }}

  try {{
    const s = await (await fetch('/gateway/stats')).json();
    document.getElementById('t-req').textContent = s.total_requests_in_window ?? 0;
    document.getElementById('t-block').textContent = Math.round((s.block_rate ?? 0) * 100) + '%';
  }} catch {{}}

  try {{
    const c = await (await fetch('/gateway/connectivity')).json();
    document.getElementById('t-mode').textContent = c.lite_mode ? 'lite' : 'full';
    const rows = Object.entries(c.backends || {{}}).map(([k, v]) => {{
      const ok = v.reachable
        ? '<span class="pill ok">reachable</span>'
        : '<span class="pill bad">unreachable</span>';
      const tp = v.transport === 'http'
        ? '<span class="pill mut">http</span>' : '<span class="pill mut">in-process</span>';
      return `<tr><td>${{k}}</td><td>${{tp}}</td><td>${{ok}}</td><td>${{(v.detail || '').slice(0, 120)}}</td></tr>`;
    }}).join('');
    document.querySelector('#conn tbody').innerHTML = rows || '<tr><td colspan="4">none</td></tr>';
  }} catch {{
    document.querySelector('#conn tbody').innerHTML = '<tr><td colspan="4">unavailable</td></tr>';
  }}
}}
load();
</script>
</body></html>
"""


@router.get("/", response_class=HTMLResponse)
def home():
    return _HOME_HTML
