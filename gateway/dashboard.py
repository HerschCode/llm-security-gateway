"""
Tier 3: real-time monitoring dashboard. Reads gateway/logs/gateway.jsonl (the
same log every request already writes to -- no separate telemetry pipeline)
and serves both a JSON stats endpoint and a small auto-refreshing HTML page.
Deliberately plain (vanilla JS polling, no build step, no extra frontend
dependency) -- this is a portfolio project's monitoring view, not a Grafana
replacement.
"""
import json
import time
from collections import Counter, deque
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from gateway.logging_schema import LOG_PATH
from gateway.webui import SHARED_CSS, nav_html

router = APIRouter()

STATS_WINDOW_SECONDS = 300  # only consider log lines from the last 5 minutes "recent"
MAX_RECENT_LINES_SCANNED = 5000  # cap file reading cost for a long-running log


class _LogTail:
    """Incremental log reader: tracks a byte offset and only reads bytes
    appended since the last call, instead of re-reading the whole file every
    time. Found via audit: the previous implementation used
    `deque(f, maxlen=MAX_RECENT_LINES_SCANNED)`, which iterates the ENTIRE
    file to build a bounded deque -- for a long-running gateway, that's an
    O(total_lines_ever_written) disk read on every single call to
    /gateway/stats, and the dashboard polls that endpoint every 2 seconds.
    The log only grows, so this would have gotten slower and slower in
    exactly the deployment scenario the dashboard is meant to help with.

    Handles two edge cases a naive "remember the byte offset" approach would
    miss: log rotation/truncation and a partial last line (a write still in
    progress) -- an incomplete final line is left unconsumed and retried on
    the next call rather than risking a JSON parse of a half-written line.
    Rotation is detected three ways, because no single signal covers every
    style: a changed inode (rename-and-recreate), a file that shrank
    (delete-and-recreate, truncate), and a changed HEAD_BYTES prefix
    (copytruncate: same inode, and refilled past the old offset before the
    next poll, so neither of the first two fires). The head of an append-only
    file never changes, so growth alone never counts as rotation. Any of the
    three resets the tracker; `_resets` counts them."""

    HEAD_BYTES = 256

    def __init__(self):
        self._records: deque = deque(maxlen=MAX_RECENT_LINES_SCANNED)
        self._file_pos = 0
        self._inode = None
        self._head = b""
        self._resets = 0

    def _reset(self):
        self._records.clear()
        self._file_pos = 0
        self._head = b""
        self._resets += 1

    def read_all(self) -> list[dict]:
        if not LOG_PATH.exists():
            return list(self._records)

        stat = LOG_PATH.stat()
        if self._inode is not None and stat.st_ino != self._inode:
            self._reset()
        self._inode = stat.st_ino

        if stat.st_size < self._file_pos:
            self._reset()

        with open(LOG_PATH, "rb") as hf:
            head = hf.read(self.HEAD_BYTES)
        if self._head and not head.startswith(self._head):     # the start of the file changed: truncated in place and refilled
            self._reset()
        self._head = head

        with open(LOG_PATH, encoding="utf-8") as f:
            f.seek(self._file_pos)
            while True:
                line = f.readline()
                if not line or not line.endswith("\n"):
                    break  # EOF, or an in-progress write -- stop here, retry next call
                self._file_pos = f.tell()

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not all(key in record for key in ("decision", "phase", "timestamp")):
                    continue
                self._records.append(record)

        return list(self._records)


_log_tail = _LogTail()


def _read_recent_records():
    all_records = _log_tail.read_all()
    cutoff = time.time() - STATS_WINDOW_SECONDS
    return [r for r in all_records if r.get("timestamp", 0) >= cutoff]


def compute_stats():
    records = _read_recent_records()

    total = len(records)
    decisions = Counter(r["decision"] for r in records)
    by_phase = Counter(r["phase"] for r in records)
    by_layer = Counter(r.get("detection_layer_used") or "none" for r in records if r["decision"] == "block")
    latencies = [r["latency_ms"] for r in records if "latency_ms" in r]

    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    block_rate = decisions.get("block", 0) / total if total else 0.0

    recent = sorted(records, key=lambda r: r["timestamp"], reverse=True)[:20]

    return {
        "window_seconds": STATS_WINDOW_SECONDS,
        "total_requests_in_window": total,
        "block_rate": round(block_rate, 3),
        "decisions": dict(decisions),
        "by_phase": dict(by_phase),
        "blocks_by_layer": dict(by_layer),
        "avg_latency_ms": round(avg_latency, 3),
        "recent_events": [
            {
                "session_id": r["session_id"],
                "phase": r["phase"],
                "decision": r["decision"],
                "layer": r.get("detection_layer_used"),
                "matched_pattern_id": r.get("matched_pattern_id"),
                "latency_ms": round(r.get("latency_ms", 0), 2),
            }
            for r in recent
        ],
    }


@router.get("/gateway/stats")
def stats():
    return compute_stats()


DASHBOARD_HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard — LLM Security Gateway</title>
<style>{SHARED_CSS}
  .block {{ color: var(--bad); }} .allow {{ color: var(--good); }}
  .stale {{ font-size: 12px; margin-bottom: 10px; }}
</style>
</head><body>
{nav_html('dashboard')}
<div class="wrap">
  <h1>Live dashboard</h1>
  <div class="sub">From the same JSONL log every request writes. Auto-refreshes every 2s ·
    window: last 5 minutes. &nbsp;<a href="/gateway/demo">Generate some traffic →</a></div>

  <div id="stale" class="stale" hidden>
    <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--warn);
                border-radius:8px;padding:16px 18px;max-width:680px;">
      <b style="color:var(--text)">No traffic in the last 5 minutes.</b><br>
      <span style="color:var(--muted);font-size:12px">The gateway is running and ready &mdash;
      send a test prompt on the <a href="/gateway/demo">demo page</a> to see live detection in action.</span>
    </div>
  </div>
  <div class="tiles" id="tiles"></div>

  <h2>Detection by layer</h2>
  <div class="tiles" id="layer-tiles" style="grid-template-columns:repeat(3,1fr)"></div>

  <h2>Recent events (last 20)</h2>
  <p style="font-size:11px;color:var(--muted);margin:0 0 6px">
    <b>phase:</b> pre_flight = checked before reaching LLM &nbsp;|&nbsp; post_flight = checked after LLM response &nbsp;&nbsp;
    <b>decision:</b> block = stopped &nbsp;|&nbsp; allow = passed
  </p>
  <table id="events">
    <thead><tr><th>Session</th><th>Phase</th><th>Decision</th><th>Layer</th><th>Matched pattern</th><th>ms</th></tr></thead>
    <tbody></tbody>
  </table>

  <h2>Pending actions (action firewall)</h2>
  <p style="font-size:11px;color:var(--muted);margin:0 0 6px">
    Write actions the firewall will not run on its own. Deciding needs the approver token
    (<code>GATEWAY_APPROVER_TOKEN</code>); the requester cannot approve their own request.
    <b>risk high</b> = an argument was copied from untrusted content.
  </p>
  <table id="actions">
    <thead><tr><th>Id</th><th>Requested by</th><th>Tool</th><th>Arguments</th><th>Risk</th><th>Why / evidence</th><th></th></tr></thead>
    <tbody></tbody>
  </table>
  <p id="actions-empty" style="font-size:12px;color:var(--muted)" hidden>No pending actions.</p>

  <h2>Backends &amp; connectivity</h2>
  <table id="conn"><thead><tr><th>Backend</th><th>Transport</th><th>Reachable</th><th>Detail</th></tr></thead><tbody></tbody></table>
</div>

<script>
const ESC = {{'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}};
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ESC[c]);
async function refresh() {{
  try {{
    const d = await (await fetch('/gateway/stats')).json();
    document.getElementById('stale').hidden = d.total_requests_in_window !== 0;
    document.getElementById('tiles').innerHTML = `
      <div class="tile"><div class="k">Requests (5min)</div><div class="v">${{d.total_requests_in_window}}</div></div>
      <div class="tile"><div class="k">Block rate</div><div class="v">${{(d.block_rate * 100).toFixed(0)}}%</div><div class="ctx">% of requests flagged as injection attempts</div></div>
      <div class="tile"><div class="k">Avg latency</div><div class="v">${{d.avg_latency_ms}}ms</div><div class="ctx">per-request detection overhead (pre-flight)</div></div>
      <div class="tile"><div class="k">Allowed / Blocked</div><div class="v">${{d.decisions.allow || 0}} / ${{d.decisions.block || 0}}</div><div class="ctx">in last 5 min window</div></div>`;
    document.querySelector('#events tbody').innerHTML = d.recent_events.map(e => `
      <tr><td>${{esc(e.session_id)}}</td><td>${{esc(e.phase)}}</td><td class="${{e.decision === 'block' ? 'block' : 'allow'}}">${{esc(e.decision)}}</td>
      <td>${{esc(e.layer || '-')}}</td><td>${{esc(e.matched_pattern_id || '-')}}</td><td>${{esc(e.latency_ms)}}</td></tr>`).join('');
    const bl = d.blocks_by_layer || {{}};
    const layerLabels = {{'rule_based': 'Rule-based', 'embedding_similarity': 'Embedding similarity (off by default)', 'scratch_classifier': 'MLP classifier'}};
    document.getElementById('layer-tiles').innerHTML = Object.entries(layerLabels).map(([k, label]) =>
      `<div class="tile"><div class="k">${{label}}</div><div class="v">${{bl[k] || 0}} blocks</div></div>`
    ).join('');
  }} catch {{}}
}}
let approver = null;
function credentials() {{
  if (approver) return approver;
  const id = prompt('Approver user id (must differ from the requester):');
  const role = prompt('Approver role (manager or admin):', 'manager');
  const token = prompt('Approver token:');
  if (!id || !role || !token) return null;
  approver = {{id, role, token}};
  return approver;
}}
async function loadActions() {{
  try {{
    const rows = await (await fetch('/gateway/actions/approvals?status=pending')).json();
    document.getElementById('actions-empty').hidden = rows.length !== 0;
    document.querySelector('#actions tbody').innerHTML = rows.map(r => {{
      const ev = (r.evidence && r.evidence.tainted || []).map(t =>
        `${{esc(t.field)}} copied from ${{esc(t.source)}}: <i>${{esc(t.snippet)}}</i>`).join('<br>');
      return `<tr><td>${{esc(r.id)}}</td><td>${{esc(r.requester_id)}} (${{esc(r.requester_role)}})</td><td>${{esc(r.tool)}}</td>
        <td><code>${{esc(JSON.stringify(r.args))}}</code></td>
        <td class="${{r.risk === 'high' ? 'block' : ''}}">${{esc(r.risk)}}</td>
        <td>${{esc((r.reasons || []).join('; '))}}${{ev ? '<br>' + ev : ''}}</td>
        <td><button data-id="${{esc(r.id)}}" data-verb="approve">Approve</button>
            <button data-id="${{esc(r.id)}}" data-verb="deny">Deny</button></td></tr>`;
    }}).join('');
  }} catch {{}}
}}
document.addEventListener('click', async ev => {{
  const b = ev.target.closest('button[data-verb]');
  if (!b) return;
  const cred = credentials();
  if (!cred) return;
  const res = await fetch(`/gateway/actions/approvals/${{encodeURIComponent(b.dataset.id)}}/${{b.dataset.verb}}`, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json', 'X-Approver-Token': cred.token}},
    body: JSON.stringify({{approver_id: cred.id, approver_role: cred.role}}),
  }});
  if (!res.ok) {{
    if (res.status === 401) approver = null;
    alert(`${{res.status}}: ${{(await res.json()).detail}}`);
  }}
  loadActions();
}});
async function loadConn() {{
  try {{
    const c = await (await fetch('/gateway/connectivity')).json();
    document.querySelector('#conn tbody').innerHTML = Object.entries(c.backends || {{}}).map(([k, v]) => {{
      const ok = v.reachable ? '<span class="pill ok">reachable</span>' : '<span class="pill bad">unreachable</span>';
      const tp = `<span class="pill mut">${{v.transport === 'http' ? 'http' : 'in-process'}}</span>`;
      return `<tr><td>${{esc(k)}}</td><td>${{tp}}</td><td>${{ok}}</td><td>${{esc((v.detail || '').slice(0, 120))}}</td></tr>`;
    }}).join('');
  }} catch {{}}
}}
refresh(); loadConn(); loadActions();
setInterval(refresh, 2000);
setInterval(loadActions, 3000);
setInterval(loadConn, 15000);
</script>
</body></html>
"""


@router.get("/gateway/dashboard", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML
