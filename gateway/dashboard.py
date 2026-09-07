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
    The log only grows (no rotation exists yet -- a separate, undone item),
    so this would have gotten slower and slower in exactly the deployment
    scenario the dashboard is meant to help with.

    Handles two edge cases a naive "remember the byte offset" approach would
    miss: log rotation/truncation (detected via inode change or file
    shrinking, both reset the tracker) and a partial last line (a write
    still in progress) -- an incomplete final line is left unconsumed and
    retried on the next call rather than risking a JSON parse of a
    half-written line."""

    def __init__(self):
        self._records: deque = deque(maxlen=MAX_RECENT_LINES_SCANNED)
        self._file_pos = 0
        self._inode = None

    def read_all(self) -> list[dict]:
        if not LOG_PATH.exists():
            return list(self._records)

        stat = LOG_PATH.stat()
        if self._inode is not None and stat.st_ino != self._inode:
            self._records.clear()
            self._file_pos = 0
        self._inode = stat.st_ino

        if stat.st_size < self._file_pos:
            self._file_pos = 0
            self._records.clear()

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


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>LLM Security Gateway -- Live Dashboard</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
    .stat-box { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }
    .stat-label { font-size: 12px; color: #8b949e; }
    .stat-value { font-size: 24px; font-weight: bold; color: #58a6ff; }
    table { width: 100%; border-collapse: collapse; background: #161b22; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #30363d; font-size: 13px; }
    th { color: #8b949e; }
    .block { color: #f85149; }
    .allow { color: #3fb950; }
    .stale-warning { color: #d29922; margin-bottom: 10px; }
  </style>
</head>
<body>
  <h1>LLM Security Gateway -- Live Dashboard</h1>
  <div id="stale" class="stale-warning" style="display:none;">
    No requests seen in the last window -- send some traffic through /gateway/chat to populate this.
  </div>
  <div class="stats-grid" id="stats-grid"></div>
  <h3>Recent events (last 20)</h3>
  <table id="events-table">
    <thead><tr><th>Session</th><th>Phase</th><th>Decision</th><th>Layer</th><th>Matched pattern</th><th>Latency (ms)</th></tr></thead>
    <tbody></tbody>
  </table>
  <p style="color:#8b949e; font-size: 12px;">Auto-refreshes every 2s. Window: last 5 minutes of logged requests.</p>

  <script>
    async function refresh() {
      const res = await fetch('/gateway/stats');
      const data = await res.json();

      document.getElementById('stale').style.display = data.total_requests_in_window === 0 ? 'block' : 'none';

      const grid = document.getElementById('stats-grid');
      grid.innerHTML = `
        <div class="stat-box"><div class="stat-label">Requests (5min)</div><div class="stat-value">${data.total_requests_in_window}</div></div>
        <div class="stat-box"><div class="stat-label">Block rate</div><div class="stat-value">${(data.block_rate * 100).toFixed(0)}%</div></div>
        <div class="stat-box"><div class="stat-label">Avg latency</div><div class="stat-value">${data.avg_latency_ms}ms</div></div>
        <div class="stat-box"><div class="stat-label">Allowed / Blocked</div><div class="stat-value">${data.decisions.allow || 0} / ${data.decisions.block || 0}</div></div>
      `;

      const tbody = document.querySelector('#events-table tbody');
      tbody.innerHTML = data.recent_events.map(e => `
        <tr>
          <td>${e.session_id}</td>
          <td>${e.phase}</td>
          <td class="${e.decision}">${e.decision}</td>
          <td>${e.layer || '-'}</td>
          <td>${e.matched_pattern_id || '-'}</td>
          <td>${e.latency_ms}</td>
        </tr>
      `).join('');
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"""


@router.get("/gateway/dashboard", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML
