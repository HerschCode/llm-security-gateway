"""
Interactive demo surface (Phase 3 of the portfolio-completion plan).

The monitoring dashboard (`gateway/dashboard.py`) shows aggregate live traffic.
This module is the other half: a single page where a visitor picks (or types)
an attack, and sees the *same prompt* run two ways at once --

  * straight at the backend (gateway bypassed), and
  * through the full gateway pipeline

-- side by side, with the verdict, which layer fired, the phase, and the
latency for each. Built on the exact same `GatewayMiddleware` and adapters the
real service uses (no separate mock path).

Endpoints:
  GET  /gateway/demo         -> the HTML page
  GET  /gateway/demo/cases   -> curated corpus cases
  POST /gateway/demo/run     -> {prompt, backend} -> both results

Abuse controls (this endpoint can reach an LLM-backed backend):
  * per-IP fixed-window rate limit -- DEMO_RATE_LIMIT (default 20) requests per
    DEMO_RATE_WINDOW seconds (default 60). Returns HTTP 429.
  * optional hard gate -- if DEMO_API_KEY is set, /gateway/demo/run requires an
    `X-Demo-Key` header matching it.
"""
import os
import time
from collections import deque
from pathlib import Path

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from gateway.adapters.operations_assistant_adapter import BACKEND_ERROR_PREFIX
from gateway.webui import SHARED_CSS, nav_html

router = APIRouter()

_CORPUS_PATH = Path(__file__).resolve().parent.parent / "corpus" / "injection_cases.yaml"

_FEATURED_IDS = [
    "GW-001",  # direct_injection       -- rule_based catches this outright
    "GW-002",  # direct_injection       -- authority impersonation
    "GW-005",  # indirect_injection
    "GW-008",  # multi_turn_jailbreak
    "GW-010",  # encoding_obfuscation
    "GW-016",  # tool_scope_escalation
    "GW-019",  # direct_injection, expected_behavior=allow -- negative control
]

_RATE_LIMIT = int(os.environ.get("DEMO_RATE_LIMIT", "20"))
_RATE_WINDOW = float(os.environ.get("DEMO_RATE_WINDOW", "60"))
_DEMO_API_KEY = os.environ.get("DEMO_API_KEY", "")
_LITE = os.environ.get("GATEWAY_LITE", "").lower() in ("1", "true", "yes")

# ip -> deque[timestamps]. In-process only (single Render instance) -- a
# multi-instance deploy would need a shared store, same caveat as the session
# trackers. Good enough to stop one script hammering the LLM-backed path.
_hits: dict[str, deque] = {}


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limited(ip: str) -> bool:
    now = time.time()
    dq = _hits.setdefault(ip, deque())
    while dq and now - dq[0] > _RATE_WINDOW:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT:
        return True
    dq.append(now)
    if len(_hits) > 2000:  # crude cap so a spray of IPs can't grow this forever
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > _RATE_WINDOW][:1000]:
            _hits.pop(k, None)
    return False


def _load_cases():
    with open(_CORPUS_PATH, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    by_id = {c["id"]: c for c in raw}
    out = []
    for cid in _FEATURED_IDS:
        c = by_id.get(cid)
        if not c:
            continue
        out.append({
            "id": c["id"],
            "category": c["category"],
            "vector": c.get("vector", ""),
            "payload": c["payload"].strip(),
            "expected_behavior": c.get("expected_behavior", ""),
        })
    return out


@router.get("/gateway/demo/cases")
def demo_cases():
    return {"cases": _load_cases()}


class DemoRunRequest(BaseModel):
    prompt: str
    backend: str = "stub_ops_agent"
    session_id: str = "demo-session"
    role: str = "employee"
    user_id: str = "demo-user"


def _summarize_trace(resp):
    """Pull the human-relevant bits out of GatewayResponse.trace."""
    trace = resp.trace or {}
    phase = trace.get("phase")
    layer = None
    per_layer = trace.get("per_layer") or {}
    for name, info in per_layer.items():
        if info.get("blocked"):
            layer = name
            break
    if not layer and phase == "post_flight":
        layer = "post_flight_checks"
    if not layer and trace.get("session_check"):
        layer = "session_check"
    return {
        "phase": phase,
        "layer": layer,
        "per_layer": per_layer,
        "block_reason": resp.block_reason,
    }


def _is_upstream_error(text) -> bool:
    return isinstance(text, str) and text.startswith(BACKEND_ERROR_PREFIX)


@router.post("/gateway/demo/run")
def demo_run(req: DemoRunRequest, request: Request):
    if _DEMO_API_KEY and request.headers.get("x-demo-key") != _DEMO_API_KEY:
        return JSONResponse({"error": "missing_or_invalid_x_demo_key"}, status_code=401)
    if _rate_limited(_client_ip(request)):
        return JSONResponse(
            {"error": f"rate_limited: max {_RATE_LIMIT} requests per {int(_RATE_WINDOW)}s"},
            status_code=429,
        )

    from gateway.app import BACKENDS
    from gateway.middleware import GatewayMiddleware

    if req.backend not in BACKENDS:
        return {"error": f"unknown_backend:{req.backend}", "available": list(BACKENDS.keys())}

    adapter, system_prompt = BACKENDS[req.backend]

    # --- 1. Gateway bypassed: prompt goes straight at the backend ---
    t0 = time.perf_counter()
    try:
        bypass_text = adapter.send(
            req.prompt, session_id=f"{req.session_id}-bypass",
            role=req.role, user_id=req.user_id,
        )
        bypass_err = None
    except Exception as exc:  # a demo should never 500 on a backend quirk
        bypass_text = None
        bypass_err = f"{type(exc).__name__}: {exc}"
    if _is_upstream_error(bypass_text):
        bypass_err = bypass_text
        bypass_text = None
    bypass_ms = (time.perf_counter() - t0) * 1000

    # --- 2. Same prompt through the full gateway pipeline ---
    mw = GatewayMiddleware()
    t0 = time.perf_counter()
    gw = mw.process(
        prompt=req.prompt, session_id=f"{req.session_id}-gw",
        backend=adapter, role=req.role, system_prompt=system_prompt,
        user_id=req.user_id,
    )
    gw_ms = (time.perf_counter() - t0) * 1000
    gw_upstream_error = _is_upstream_error(gw.response_text)

    return {
        "prompt": req.prompt,
        "backend": req.backend,
        "lite_mode": _LITE,
        "bypassed": {
            "allowed": bypass_err is None,
            "response": bypass_text,
            "error": bypass_err,
            "upstream_error": bool(bypass_err),
            "latency_ms": round(bypass_ms, 2),
        },
        "gateway": {
            "allowed": gw.allowed and not gw_upstream_error,
            "response": None if gw_upstream_error else gw.response_text,
            "error": gw.response_text if gw_upstream_error else None,
            "upstream_error": gw_upstream_error,
            "latency_ms": round(gw_ms, 2),
            **_summarize_trace(gw),
        },
    }


_LITE_BANNER = """
  <div class="banner">
    &#x26A1; <b>Lite mode</b> &mdash; Layers 1 &amp; 2 active (rule-based + embedding similarity).
    Layer 3 (MLP classifier) requires 512&nbsp;MB+ RAM and runs locally via
    <code>docker compose up</code>. All pre/post-flight checks run on this deploy.
  </div>
"""

_DEMO_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo — LLM Security Gateway</title>
<style>
__SHARED_CSS__
  body { padding: 0; }
  .democontent { padding: 24px; max-width: 1000px; margin: 0 auto; }
  h1 { color: var(--accent); margin: 0 0 4px; font-size: 20px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 16px; max-width: 780px; }
  .sub a { color: var(--accent); }
  .banner { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--warn);
            border-radius: 6px; padding: 10px 12px; font-size: 12px; color: var(--text);
            margin-bottom: 18px; max-width: 780px; }
  .banner code { color: var(--muted); }
  .controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; margin-bottom: 12px; }
  label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; text-transform: uppercase; letter-spacing: .04em; }
  select, textarea, button { font-family: inherit; font-size: 13px; background: var(--surface);
         color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; }
  textarea { width: 100%; min-height: 90px; resize: vertical; margin-bottom: 12px; }
  button { background: #238636; border-color: #2ea043; color: #fff; cursor: pointer; font-weight: 600; padding: 9px 18px; }
  button:disabled { opacity: .5; cursor: default; }
  .case-vector { font-size: 12px; color: var(--muted); margin: -4px 0 4px; }
  .case-explain { font-size: 12px; color: var(--muted); margin: 0 0 10px; font-style: italic; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 8px; }
  @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
  .panel h2 { font-size: 13px; margin: 0 0 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  .verdict { font-size: 22px; font-weight: 700; margin-bottom: 8px; }
  .allowed { color: var(--bad); }     /* backend complied with an attack = bad */
  .blocked { color: var(--good); }   /* gateway stopped it = good */
  .neutral { color: var(--muted); }
  .errored { color: var(--warn); }   /* upstream backend failure -- not a verdict */
  .meta { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
  .meta b { color: var(--text); }
  .resp { white-space: pre-wrap; word-break: break-word; background: var(--bg);
          border: 1px solid var(--surface2); border-radius: 6px; padding: 10px; font-size: 12.5px; max-height: 260px; overflow: auto; }
  .layers { font-size: 11px; margin-top: 8px; }
  .layers span { display: inline-block; margin: 2px 4px 0 0; padding: 2px 6px; border-radius: 4px; background: var(--surface2); }
  .layers .hit { background: color-mix(in srgb, var(--good) 13%, transparent); color: var(--good); border: 1px solid color-mix(in srgb, var(--good) 33%, transparent); }
  .explanation { font-size: 12px; color: var(--muted); margin-top: 8px; font-style: italic; }
  .foot { margin-top: 20px; font-size: 12px; color: var(--muted); }
  .foot a { color: var(--accent); }
</style>
</head>
<body>
__NAV__
<div class="democontent">
  <h1>Interactive demo</h1>
  <div class="sub">
    Pick an attack (or write your own), choose a backend, and hit <b>Run</b>. The same prompt is sent
    two ways: straight at the backend with no protection, and through the gateway pipeline
    (PII redaction &rarr; injection ensemble &rarr; session checks &rarr; backend &rarr; post-flight
    role / compliance / leak checks). &nbsp;
    <a href="/gateway/dashboard">Live traffic dashboard &rarr;</a>
  </div>
  __LITE_BANNER__

  <div class="controls">
    <div>
      <label for="case">Sample attack</label>
      <select id="case"><option value="">-- custom / type below --</option></select>
    </div>
    <div>
      <label for="backend">Backend</label>
      <select id="backend"></select>
    </div>
    <button id="run">Run</button>
  </div>
  <div class="case-vector" id="vector"></div>
  <div class="case-explain" id="case-explain"></div>

  <textarea id="prompt" placeholder="Type a prompt to send through the gateway..."></textarea>

  <div class="grid">
    <div class="panel">
      <h2>Backend alone &mdash; gateway bypassed</h2>
      <div class="verdict neutral" id="b-verdict">&mdash;</div>
      <div class="meta" id="b-meta"></div>
      <div class="resp" id="b-resp"></div>
    </div>
    <div class="panel">
      <h2>Through the gateway</h2>
      <div class="verdict neutral" id="g-verdict">&mdash;</div>
      <div class="meta" id="g-meta"></div>
      <div class="resp" id="g-resp"></div>
      <div class="layers" id="g-layers"></div>
      <div class="explanation" id="g-explanation"></div>
    </div>
  </div>

  <div class="foot">
    Every number here is produced by the same <code>GatewayMiddleware</code> the deployed service runs.
    Honest caveats (detector limits, train/test leakage that was found &amp; fixed, residual
    false-positive rate) are in <code>docs/</code> &mdash; nothing is hidden for the demo.
  </div>

<script>
const $ = id => document.getElementById(id);
let CASES = [];

const CATEGORY_EXPLAINERS = {
  direct_injection: "Tries to override the system prompt by telling the model to ignore its instructions.",
  indirect_injection: "Hides attack payload in content the model is asked to process (not in the direct prompt).",
  multi_turn_jailbreak: "Uses multiple conversation turns to gradually shift the model's behaviour.",
  encoding_obfuscation: "Encodes the malicious instruction in base64 or Unicode to evade text-matching defenses.",
  tool_scope_escalation: "Attempts to call tools or access data beyond the user's authorised scope.",
};

async function loadCases() {
  const res = await fetch('/gateway/demo/cases');
  const data = await res.json();
  CASES = data.cases || [];
  const sel = $('case');
  for (const c of CASES) {
    const o = document.createElement('option');
    o.value = c.id;
    o.textContent = `${c.id}  [${c.category}]` + (c.expected_behavior === 'allow' ? '  (negative control)' : '');
    sel.appendChild(o);
  }
}

async function loadBackends() {
  const sel = $('backend');
  try {
    const res = await fetch('/gateway/backends');
    const data = await res.json();
    for (const b of (data.backends || [])) {
      const o = document.createElement('option');
      o.value = b.key;
      o.textContent = b.name || b.key;
      sel.appendChild(o);
    }
    // Prefer the real agent as default; fall back to whatever is first
    const keys = (data.backends || []).map(b => b.key);
    if (keys.includes('operations_assistant')) sel.value = 'operations_assistant';
  } catch (e) {
    const o = document.createElement('option');
    o.value = 'stub_ops_agent'; o.textContent = 'stub_ops_agent';
    sel.appendChild(o);
  }
}

$('case').addEventListener('change', e => {
  const c = CASES.find(x => x.id === e.target.value);
  $('vector').textContent = c ? c.vector : '';
  $('case-explain').textContent = c ? (CATEGORY_EXPLAINERS[c.category] || '') : '';
  if (c) $('prompt').value = c.payload;
});

function renderSide(prefix, r, isGateway) {
  const v = $(prefix + '-verdict');
  const meta = $(prefix + '-meta');
  const resp = $(prefix + '-resp');
  if (r.upstream_error || (r.error && !isGateway && !('upstream_error' in r))) {
    v.className = 'verdict errored'; v.textContent = 'UPSTREAM ERROR';
    meta.innerHTML = `<b>latency</b> ${r.latency_ms} ms &nbsp;|&nbsp; the backend itself failed &mdash; not a gateway verdict`;
    resp.textContent = r.error || 'backend error';
    if (isGateway) $('g-layers').innerHTML = '';
    return;
  }
  const allowed = r.allowed;
  if (isGateway) {
    v.className = 'verdict ' + (allowed ? 'allowed' : 'blocked');
    v.textContent = allowed ? 'ALLOWED' : 'BLOCKED';
  } else {
    v.className = 'verdict ' + (allowed ? 'allowed' : 'neutral');
    v.textContent = allowed ? 'ANSWERED (no checks)' : 'no response';
  }
  let m = `<b>latency</b> ${r.latency_ms} ms`;
  if (isGateway && !allowed) {
    m += ` &nbsp;|&nbsp; <b>phase</b> ${r.phase || '-'}`;
    m += ` &nbsp;|&nbsp; <b>layer</b> ${r.layer || '-'}`;
    if (r.block_reason) m += ` &nbsp;|&nbsp; <b>reason</b> ${r.block_reason}`;
  }
  meta.innerHTML = m;
  resp.textContent = r.response == null ? '(no response returned)' : r.response;
}

function renderLayers(r) {
  const box = $('g-layers');
  const expl = $('g-explanation');
  const pl = r.per_layer || {};
  const names = ['rule_based', 'embedding_similarity', 'scratch_classifier'];
  if (!Object.keys(pl).length) { box.innerHTML = ''; expl.textContent = ''; return; }
  box.innerHTML = names.map(n => {
    const info = pl[n];
    if (!info) return `<span>${n}: n/a</span>`;
    if (info.skipped) return `<span>${n}: skipped (${info.skipped})</span>`;
    return `<span class="${info.blocked ? 'hit' : ''}">${n}: ${info.blocked ? 'BLOCK' : 'pass'}</span>`;
  }).join('');
  // Plain-English explanation of the verdict
  const activeCount = names.filter(n => pl[n] && !pl[n].skipped).length;
  if (!r.allowed) {
    if (pl.rule_based && pl.rule_based.blocked) {
      const pid = r.block_reason || 'a known pattern';
      expl.textContent = `Matched ${pid} — classic instruction-override pattern.`;
    } else if (pl.embedding_similarity && pl.embedding_similarity.blocked) {
      expl.textContent = 'Prompt semantically similar to known attack patterns.';
    } else if (pl.scratch_classifier && pl.scratch_classifier.blocked) {
      expl.textContent = 'MLP classifier flagged as injection attempt.';
    } else if (r.layer === 'post_flight_checks') {
      expl.textContent = 'Post-flight checks caught a policy violation in the response.';
    } else {
      expl.textContent = `Blocked by ${r.layer || 'a detection layer'}.`;
    }
  } else {
    expl.textContent = `Passed all ${activeCount} active detection layer${activeCount !== 1 ? 's' : ''}.`;
  }
}

$('run').addEventListener('click', async () => {
  const prompt = $('prompt').value.trim();
  if (!prompt) return;
  $('run').disabled = true; $('run').textContent = 'Running...';
  try {
    const res = await fetch('/gateway/demo/run', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ prompt, backend: $('backend').value }),
    });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    renderSide('b', data.bypassed, false);
    renderSide('g', data.gateway, true);
    renderLayers(data.gateway);
  } finally {
    $('run').disabled = false; $('run').textContent = 'Run';
  }
});

loadCases();
loadBackends();
</script>
</div>
</body>
</html>
"""


@router.get("/gateway/demo", response_class=HTMLResponse)
def demo_page():
    return (
        _DEMO_HTML
        .replace("__SHARED_CSS__", SHARED_CSS)
        .replace("__NAV__", nav_html("demo"))
        .replace("__LITE_BANNER__", _LITE_BANNER if _LITE else "")
    )
