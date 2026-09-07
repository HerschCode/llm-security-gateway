"""
Interactive demo surface (Phase 3 of the portfolio-completion plan).

The monitoring dashboard (`gateway/dashboard.py`) shows aggregate live traffic.
This module is the other half: a single page where a visitor picks (or types)
an attack, and sees the *same prompt* run two ways at once --

  * straight at the backend (gateway bypassed), and
  * through the full gateway pipeline

-- side by side, with the verdict, which layer fired, the phase, and the
latency for each. It's deliberately the "click a link, watch it work" view a
portfolio needs, built on the exact same `GatewayMiddleware` and adapters the
real service uses (no separate mock path).

Endpoints:
  GET  /gateway/demo         -> the HTML page
  GET  /gateway/demo/cases   -> curated corpus cases, grouped by category
  POST /gateway/demo/run     -> {prompt, backend} -> both results
"""
import time
from pathlib import Path

import yaml
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

router = APIRouter()

_CORPUS_PATH = Path(__file__).resolve().parent.parent / "corpus" / "injection_cases.yaml"

# A curated subset -- enough to show every category and both a clear block and a
# clear negative control, without dumping all 36 rows into a demo dropdown.
_FEATURED_IDS = [
    "GW-001",  # direct_injection       -- rule_based catches this outright
    "GW-002",  # direct_injection       -- authority impersonation
    "GW-005",  # indirect_injection
    "GW-008",  # multi_turn_jailbreak
    "GW-010",  # encoding_obfuscation
    "GW-016",  # tool_scope_escalation
    "GW-019",  # direct_injection, expected_behavior=allow -- negative control
]


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


@router.post("/gateway/demo/run")
def demo_run(req: DemoRunRequest):
    # Imported here (not at module load) so `import gateway.demo` stays cheap
    # and this module has no import-time dependency on model files loading.
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

    return {
        "prompt": req.prompt,
        "backend": req.backend,
        "bypassed": {
            "allowed": True,  # nothing is checking -- the backend just answers
            "response": bypass_text,
            "error": bypass_err,
            "latency_ms": round(bypass_ms, 2),
        },
        "gateway": {
            "allowed": gw.allowed,
            "response": gw.response_text,
            "latency_ms": round(gw_ms, 2),
            **_summarize_trace(gw),
        },
    }


_DEMO_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM Security Gateway -- Interactive Demo</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; line-height: 1.5; }
  h1 { color: #58a6ff; margin: 0 0 4px; font-size: 20px; }
  .sub { color: #8b949e; font-size: 13px; margin-bottom: 20px; max-width: 780px; }
  .sub a { color: #58a6ff; }
  .controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; margin-bottom: 12px; }
  label { display: block; font-size: 11px; color: #8b949e; margin-bottom: 4px; text-transform: uppercase; letter-spacing: .04em; }
  select, textarea, button { font-family: inherit; font-size: 13px; background: #161b22;
         color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 8px 10px; }
  textarea { width: 100%; min-height: 90px; resize: vertical; margin-bottom: 12px; }
  button { background: #238636; border-color: #2ea043; color: #fff; cursor: pointer; font-weight: 600; padding: 9px 18px; }
  button:disabled { opacity: .5; cursor: default; }
  .case-vector { font-size: 12px; color: #8b949e; margin: -4px 0 10px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 8px; }
  @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }
  .panel h2 { font-size: 13px; margin: 0 0 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .04em; }
  .verdict { font-size: 22px; font-weight: 700; margin-bottom: 8px; }
  .allowed { color: #f85149; }        /* backend complied with an attack = bad */
  .blocked { color: #3fb950; }        /* gateway stopped it = good */
  .neutral { color: #8b949e; }
  .meta { font-size: 12px; color: #8b949e; margin-bottom: 8px; }
  .meta b { color: #c9d1d9; }
  .resp { white-space: pre-wrap; word-break: break-word; background: #0d1117;
          border: 1px solid #21262d; border-radius: 6px; padding: 10px; font-size: 12.5px; max-height: 260px; overflow: auto; }
  .layers { font-size: 11px; margin-top: 8px; }
  .layers span { display: inline-block; margin: 2px 4px 0 0; padding: 2px 6px; border-radius: 4px; background: #21262d; }
  .layers .hit { background: #3fb95022; color: #3fb950; border: 1px solid #3fb95055; }
  .foot { margin-top: 20px; font-size: 12px; color: #8b949e; }
  .foot a { color: #58a6ff; }
</style>
</head>
<body>
  <h1>LLM Security Gateway &mdash; Interactive Demo</h1>
  <div class="sub">
    Pick an attack (or write your own), choose a backend, and hit <b>Run</b>. The same prompt is sent
    two ways: straight at the backend with no protection, and through the full gateway pipeline
    (PII redaction &rarr; 3-layer injection ensemble &rarr; session checks &rarr; backend &rarr; post-flight
    role / compliance / leak checks). &nbsp;
    <a href="/gateway/dashboard">Live traffic dashboard &rarr;</a>
  </div>

  <div class="controls">
    <div>
      <label for="case">Sample attack</label>
      <select id="case"><option value="">-- custom / type below --</option></select>
    </div>
    <div>
      <label for="backend">Backend</label>
      <select id="backend">
        <option value="stub_ops_agent">stub_ops_agent (undefended stand-in)</option>
        <option value="project2_agent">project2_agent (reconstruction, has own auth)</option>
        <option value="trivial_echo">trivial_echo</option>
      </select>
    </div>
    <button id="run">Run</button>
  </div>
  <div class="case-vector" id="vector"></div>

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

$('case').addEventListener('change', e => {
  const c = CASES.find(x => x.id === e.target.value);
  $('vector').textContent = c ? c.vector : '';
  if (c) $('prompt').value = c.payload;
});

function renderSide(prefix, r, isGateway) {
  const v = $(prefix + '-verdict');
  const meta = $(prefix + '-meta');
  const resp = $(prefix + '-resp');
  if (r.error) {
    v.className = 'verdict neutral'; v.textContent = 'ERROR';
    meta.innerHTML = ''; resp.textContent = r.error; return;
  }
  const allowed = r.allowed;
  if (isGateway) {
    v.className = 'verdict ' + (allowed ? 'allowed' : 'blocked');
    v.textContent = allowed ? 'ALLOWED' : 'BLOCKED';
  } else {
    // backend alone: "answered" is neutral-to-bad, there's no judgement here
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
  const pl = r.per_layer || {};
  const names = ['rule_based', 'embedding_similarity', 'scratch_classifier'];
  if (!Object.keys(pl).length) { box.innerHTML = ''; return; }
  box.innerHTML = names.map(n => {
    const info = pl[n];
    if (!info) return `<span>${n}: n/a</span>`;
    return `<span class="${info.blocked ? 'hit' : ''}">${n}: ${info.blocked ? 'BLOCK' : 'pass'}</span>`;
  }).join('');
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
</script>
</body>
</html>
"""


@router.get("/gateway/demo", response_class=HTMLResponse)
def demo_page():
    return _DEMO_HTML
