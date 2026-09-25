# Action firewall (Phase 3)

The rest of this gateway inspects **text**. Once an agent can call tools, a prompt injection that slips past the text layers becomes an
**action**, so this package adds a second, independent control point that decides what an agent is allowed to *do*.

```
                    +-------------------+      allow            +--------------------+
 agent / MCP client |  ActionFirewall   |--------------------->  | tools / MCP server |
 ---- tool call --->|  1 policy         |      deny  -> error   +--------------------+
                    |  2 taint          |      require_approval -> queue -> human -> executed (once)
                    |  3 approval gate  |
                    +-------------------+  every decision -> audit log (PII-redacted)
```

Files: `gateway/actions/{policy,taint,approvals,firewall,api,mcp_proxy,demo_upstream}.py`, policy in
[`config/tool_policies.yaml`](../config/tool_policies.yaml), corpus in [`corpus/agentic_attacks.yaml`](../corpus/agentic_attacks.yaml),
measurements in [`reports/p3_action_firewall.json`](../reports/p3_action_firewall.json).

## Demo (`python -X utf8 -m scripts.demo_action_firewall`)

A scripted "naive agent" reads a poisoned policy document and obeys it. Same agent, same undefended server:

- **Direct:** the server records `propose_intervention(ZX-9000)` and `delete_all_records(2026-Q3)`: both carried out.
- **Through the firewall:** `propose_intervention(ZX-9000)` is denied (argument copied from untrusted content, stage `taint`),
  `delete_all_records` is denied (not in the policy). Effects on the system: none. A clean request in the same session
  ("escalate CASE-4471", said by the user) is held for approval, the requester's own approval attempt is refused, a second
  manager approves, and it runs exactly once.

The agent is a script, not a model. The demo shows what the firewall does once an agent is hijacked, not how often real models are.

## The three controls

1. **Policy** (`policy.py`): default-deny, per-tool, first-matching-rule. A rule names roles and per-argument constraints
   (`in`, `pattern`, `not_pattern`, `max_length`, `min`/`max`, `type`, `equals: $principal.user_id` for own-records-only). `strict_args`
   rejects any argument the rule does not declare (kills smuggled parameters like `skip_approval=true`). Every rule of a write tool must set
   `approval: required`, checked at load time. The file is validated on load: unknown keys raise, a typo cannot silently weaken it.
2. **Taint** (`taint.py`): every text that enters the agent's context is registered with a trust label (the user's messages and outputs
   of trusted tools are trusted; retrieved documents, uploads and outputs of tools marked untrusted are not). A write-tool argument is
   *tainted* when most of its word 3-grams (or the exact word sequence, for one or two words) appear in untrusted text and in no trusted text.
   Per argument, the policy says `deny` (used for `target`) or `flag` (used for `reason`: raises risk to high, still needs approval).
3. **Approval gate** (`approvals.py`): writes are queued in SQLite, not run. Only a manager or admin may decide; the requester may not
   decide their own request (separation of duties); decisions are final; requests expire after 24 h; the queue is capped at 200 pending;
   execution is tracked separately from approval.

## MCP proxy mode (`python -m gateway.actions.mcp_proxy --role manager --user-id mona -- <upstream command>`)

A stdio JSON-RPC filter between an MCP client and any MCP server. `tools/call` is authorized (allow, deny, or held); results of
`tools/call`, `resources/read` and `prompts/get` become taint sources; `tools/list` is filtered to what the caller's role may use;
approved actions are executed by the proxy itself, once, after the policy is evaluated *again* (the policy or role may have changed while
pending). Hardening found while testing it against hostile input: a `tools/call` sent as a **notification** (no id) would have run
unchecked, so it is dropped; **unknown protocol methods** are blocked (default-deny at the protocol level); `arguments` that are not an
object are rejected instead of being coerced for checking while the original is forwarded (a parser differential); the proxy parses each message once and forwards the re-serialised object it checked, so a duplicate-key JSON trick should not reach upstream (true by
construction; not separately tested); ids starting `fw-` are reserved.

**Verified against operations-assistant's real MCP server** (the `mcp` SDK, a real handshake): an employee sees 7 of the 9 tools
(`get_management_report` and `get_supplier_performance` are hidden and blocked), an unlisted tool is blocked, and allowed calls reach the real
server. That server exposes only read tools (`propose_intervention` lives on its LangGraph path, not on MCP), so the *write* behaviour is
demonstrated against `demo_upstream.py`, a small undefended stdlib MCP server that mirrors P2's tool names. It is tested over real stdio in
`tests/test_action_mcp_proxy.py`.

## Results (`python -X utf8 -m scripts.evaluate_action_firewall`)

54 scenarios: 45 harmful, 9 benign controls, in 8 categories. The corpus assumes the worst case: the agent has been hijacked and
emits the attacker's call. It measures whether the **action** is stopped, and says nothing about how often real models are hijacked.

| Category | Scenarios | Stopped by policy | Stopped by taint | Held for approval | Executed |
|---|---|---|---|---|---|
| Indirect injection into a write | 8 | 0 | 7 | 1 | 0 |
| Tool-scope escalation | 7 | 7 | 0 | 0 | 0 |
| Cross-user action | 6 | 6 | 0 | 0 | 0 |
| Exfiltration through arguments | 7 (+1 evasion) | 7 | 0 | 0 | 0 |
| Confused deputy | 6 | 3 | 3 | 0 | 0 |
| Schema abuse | 5 | 5 | 0 | 0 | 0 |
| **In-scope harmful total** | **39** | **28** | **10** | **1** | **0** |
| Known evasions (kept separate) | 6 | 0 | 0 | **6** | 0 |
| Benign controls | 9 | 0 false blocks | | 1 held at high risk (a manager copied policy text into a reason) | |

Ground truth: the firewall's decision matches the corpus's expected outcome on 53 of 59 calls; all 6 mismatches are the known evasions.

**Text layers, for comparison** (attribution corrected during this work: 5 scenarios first looked "stopped by text layers" but were
false positives on innocuous messages, not detections):
- as deployed (they inspect the user message only): detected **2 of 2** attacks that were in the user message; blocked **5 of 52**
  innocuous user messages; none of the indirect-injection scenarios (their user messages are innocuous);
- hypothetical, if retrieved content were scanned with the same ensemble: detected the injection in **6 of 20** scenarios that had
  injected context; flagged clean context in 0.

### How to read this

- **"Executed: 0" is true by construction, not proof of unbreakability.** Every write requires approval, and harmful reads are denied by role or
  argument rules. What it says is that nothing harmful runs *without a human or a denial* in this corpus.
- **The boring controls do most of the work**: 28 of 39 in-scope harmful scenarios were stopped by default-deny, role gates, strict arguments
  and argument patterns, not by the taint heuristic. Taint adds the 10 that policy alone would have let through to a human.
- **6 of 45 harmful scenarios (13%) reach the approval queue** because taint misses them (7 of 45 counting the one in-scope request that was
  deliberately flagged high-risk rather than blocked): paraphrase, spelling a value out, base64,
  translation, an abbreviation, and sensitive figures that arrived through a *trusted* tool and were moved into a reason. The approval gate
  is the backstop, so a reviewer has to catch these. `tests/test_action_taint.py` and `tests/test_action_corpus.py` pin them as known
  misses so an improvement shows up as a test change.
- **Authorship**: the corpus and the firewall have the same author, so the results are optimistic. An independent red-team is Phase 4.

## What is implemented vs not

Implemented: default-deny capability policy with argument constraints; string-overlap provenance tracking; human approval queue with
separation of duties; audit log; HTTP decision point; stdio MCP proxy; dashboard panel.

**Not CaMeL, and not claiming to be.** CaMeL (Debenedetti et al., 2025) uses a privileged model that only sees trusted input to plan the
actions, a quarantined model that reads untrusted data but cannot call tools, and an interpreter that tracks data flow exactly. Nothing
here does that: taint is a heuristic on observable strings, and it is evaded by anything that rewrites the text. The dual-LLM /
capability-based approach is the stronger design; it needs control of the agent's architecture, which a proxy does not have.

Not implemented:
- authentication of principals or approvers: the MCP stdio transport has none, so `--role/--user-id` are asserted by whoever launches the proxy,
  and approvers are checked by a shared token plus a caller-supplied id (put SSO in front for real use);
- HTTP transports (SSE, streamable HTTP) for the MCP proxy;
- the user's chat message in MCP mode: the proxy cannot see it, so it cannot tell "the user typed this" from "a document said this". It errs
  toward suspicion; hosts that can should register it via `POST /gateway/actions/sources`;
- taint across sessions or restarts (in memory, bounded per session); rate limiting beyond the per-session write cap;
- multi-instance deployment (session state is in process; the approval queue is SQLite on local disk).

## Decisions and side-findings

- **YAML evaluator instead of OPA/Rego or Cedar**: OPA needs a separate server or binary and Cedar's Python bindings are a native dependency; this
  project targets a torch-free 512 MB tier and the surface is small (role x tool x argument). The file format is close to what a Cedar migration
  would need. A real deployment with many policies should use Cedar or OPA.
- **Found while building it:** the dashboard interpolated request-controlled fields (`session_id`, matched pattern) into `innerHTML`, a stored XSS
  in a security product's own dashboard (fixed: everything is escaped, verified in a browser with a malicious session id); `Dockerfile.render` did not
  copy `config/`, so the new endpoints would have failed on Render (fixed); the unauthenticated endpoints had unbounded memory and queue growth on
  a 512 MB host (fixed with caps and tests); one expiry test depended on clock resolution and was flaky (made deterministic).
- **Public demo posture:** approvals fail closed (HTTP 503) unless `GATEWAY_APPROVER_TOKEN` is set, and `render.yaml` does not set it. The deployed instance was not
  redeployed or re-checked as part of this work.

## Reproduce

```
python -X utf8 -m scripts.demo_action_firewall          # side-by-side demo
python -X utf8 -m scripts.evaluate_action_firewall      # reports/p3_action_firewall.json
pytest tests/test_action_*.py                            # 142 tests
```
