# Architecture

![Architecture](architecture.svg)

The gateway has two control points that share a logger and a PII scrubber but otherwise work differently.

* The **text pipeline** reads prompts and responses. Its detectors are heuristic and learned (regex rules, a small classifier), so they have measured, non-zero miss and false-positive rates.
* The **action firewall** does not read the conversation. It receives a *tool call* (tool name, arguments, who is asking, which session) and answers `allow`, `deny` or `require_approval` from a policy file, so
  most of its decisions are deterministic. The one heuristic part is the taint check, and its limits are documented in [`action-firewall.md`](action-firewall.md).

Neither is a substitute for the other: the text layers stop crude messages and cannot stop a call an already-hijacked agent decides to make, and the action firewall cannot tell whether a message was an attack.
The red-team report ([`../reports/redteam-2026-09.md`](../reports/redteam-2026-09.md)) measures that split.

## 1. Text pipeline

`GatewayMiddleware.process()` in [`gateway/middleware.py`](../gateway/middleware.py); the HTTP wrapper is [`gateway/app.py`](../gateway/app.py) (`POST /gateway/chat`, `/gateway/chat/stream`).

| # | Stage | What it does | Code |
|---|---|---|---|
| 0 | Request limits | Body over 256 KiB is a 413 (also for chunked uploads); a prompt over 20,000 characters is a 422; more than 120 requests a minute from one client IP is a 429 | `limits.py`, `ip_limits.py`, `app.py` |
| 1 | PII | Detected before anything else sees the text, then redacted (`[REDACTED_EMAIL]`) or, with `PII_MODE=pseudonymize`, replaced by a stable per-session token that can be restored in the answer for allowed roles. Regex backend by default, with Aadhaar (Verhoeff), PAN and Indian phone numbers; Presidio is an optional backend | `pii.py`, `pii_in.py`, `pii_presidio.py`, `pseudonymize.py` |
| 2 | Two texts | The redacted prompt becomes a *detection* text (`normalize`: Unicode folding, leetspeak and homoglyphs, base64 and hex decoding) and a *forward* text (`sanitize`: removal-only cleanup). The backend only ever gets the forward text, never the decoded one | `text_normalizer.py` |
| 3 | Session checks | 20 requests per 60 seconds per session, and a burst check against the session's own history | `session_checks.py` |
| 4 | Session context | The session's earlier clean turns are joined to the current message for detection only, so a payload split across turns can still match. A blocked turn is not added | `session_checks.py` (content tracker) |
| 5 | Detection, block on any | 30 regex rules; the rules again on candidate readings (ROT13, Atbash, reversed) of the text; the numpy classifier (a 2 MB MLP over mean-pooled token embeddings, served without torch and checked for bit-parity with the trained model). A similarity layer exists but is off by default. Then a check for invisible Unicode tag characters | `detectors/`, `middleware.py` |
| 6 | Adaptive thresholds | Every block raises the session's risk score (0.3, decaying 0.01 per second) and lowers the classifier's threshold for that session | `adaptive_threshold.py` |
| 7 | Backend | One method, `send()` (and `stream()`): stub, echo, the Project 2 reconstruction, or the real operations-assistant | `adapters/` |
| 8 | Post-flight | The response is checked for role-restricted data (redacted when found), jailbreak compliance markers and a system-prompt leak. A hit is also counted as a block for the session's risk score. On the streaming route the checks re-run on the growing buffer after every chunk and cut the stream off | `role_exposure.py`, `response_checks.py` |
| 9 | Reveal and log | Pseudonym tokens are restored for permitted roles; every stage writes a JSONL audit record (decision, layer, pattern id, latency; the prompt itself is not logged, though a streaming cut-off keeps the last 80 characters of the response) | `pseudonymize.py`, `logging_schema.py` |

Detectors are loaded once. Their artifacts are hashed against `models/MANIFEST.sha256` before loading (`MODEL_INTEGRITY`: `enforce` in the images and CI, `warn` locally).

## 2. Action firewall

[`gateway/actions/`](../gateway/actions), as an HTTP decision point (`/gateway/actions/*`) and as a stdio MCP proxy that sits between an MCP client and any MCP server.

```
tool result  ->  observe / sources    register the text as trusted or untrusted (trust comes from the policy)
tool call    ->  authorize
                   1. policy     default deny; role gates; argument constraints; unknown arguments rejected     -> deny
                   2. taint      does a write's argument overlap untrusted text seen in this session?            -> deny or flag
                   3. approval   every write tool waits in the queue; the requester cannot decide their own     -> require_approval
                 every decision is appended to the audit log with string arguments PII-redacted
```

* **Policy** ([`config/tool_policies.yaml`](../config/tool_policies.yaml), `policy.py`): tools not listed do not exist for any role; every rule of a write tool must set `approval: required`, or the policy refuses to load.
* **Taint** (`taint.py`): a string-overlap heuristic over canonicalised text (case, accents, invisible characters, number words, base64 and hex, identifier spelling). It catches copied values and misses paraphrase,
  translation and data that arrives through a trusted tool.
* **Approvals** (`approvals.py`, SQLite): pending requests survive a restart; approving needs an approver role and a different identity from the requester. Identity is asserted by the caller, not authenticated.
* **MCP proxy** (`mcp_proxy.py`): forwards allowed calls, answers denied ones itself, queues the rest and runs them after approval; filters `tools/list` to what the role may use. Only the stdio transport exists.
* The firewall never executes a tool: it returns a verdict and the caller acts on it.

## 3. State and where it lives

| State | Where | Survives a restart | Shared across instances |
|---|---|---|---|
| Rate-limit counters, session context, risk scores, pseudonym vaults, taint spans | Process memory (bounded) | No | No |
| Approval queue | SQLite (`GATEWAY_APPROVALS_DB`) | Yes | No |
| Audit logs | JSONL under `logs/` (rotation-safe on Windows and Linux) | Yes | No |

Running more than one instance therefore needs a shared store for the first row. That is listed under limitations in [`../SECURITY.md`](../SECURITY.md); it is not built.

## 4. Trust boundaries

Untrusted: the caller's prompt and session id, tool results and retrieved documents, the backend's response. Trusted: the policy file, the model artifacts (integrity-checked), the process environment.
The threat model, by STRIDE category, with the test and status of each mitigation, is in [`../SECURITY.md`](../SECURITY.md).

Older architecture text, from before the action firewall and the current default ensemble, is kept in [`architecture-notes.md`](architecture-notes.md).
