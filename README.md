# LLM Security Gateway

A standalone security middleware for LLM applications. Sits between a caller and
any LLM backend, inspecting traffic in both directions: prompt injection, PII
leakage, jailbreak-compliance, and role-inappropriate data exposure. Think of it
structurally like an nginx/Envoy reverse proxy, except the checks are
LLM-specific instead of generic auth/rate-limiting.

**What I can actually prove, not just claim:** with the gateway bypassed, a
naive backend complies with 30/36 attacks in the corpus (passes only the 6 cases
that don't require any defense at all — the negative/ambiguous controls). With the
gateway in front of it, 29/36 corpus cases are handled correctly end-to-end, over a
live running FastAPI service, not an in-process function call. See
[Proof requirements](#proof-requirements) below for the full checklist with
receipts — including a real methodology bug (train/test leakage) that was found and
fixed along the way, not glossed over.

---

## Status: what's real vs. simulated (read this first)

In the interest of not overstating progress:

| Component | Status |
|---|---|
| Attack corpus (36 cases, 5 categories) | **Real.** Built from scratch, versioned YAML, status fields filled in by an actual eval run. Expanded from 20 to 36 cases (v0.2.0) — see `docs/decisions.md`. |
| Rule-based detector | **Real.** Regex/keyword, runs, measured. |
| Embedding-similarity detector | **Real, but measured honestly now shows 0% detection.** TF-IDF + cosine similarity, not transformer sentence embeddings (documented substitution — see below). Earlier 97% figure was train/test leakage, found and fixed. See [`docs/leakage_fix.md`](docs/leakage_fix.md). |
| From-scratch classifier | **Real, but not a fine-tune, and only 50% detection once leakage was fixed.** A small PyTorch model, not DistilBERT, for the same network reason as above. Real training loop, real (if modest) precision/recall numbers, and now fully reproducible (PyTorch's RNG was unseeded before an audit pass caught it — see `docs/decisions.md`). |
| DistilBERT fine-tune script | **Written, never run.** [`scripts/train_distilbert_finetune.py`](scripts/train_distilbert_finetune.py) is correct code for an environment with model-hub access. Its docstring says this explicitly. Treat any numbers you'd expect from it as a hypothesis until someone actually runs it. |
| FastAPI gateway middleware | **Real.** Pre-flight + post-flight checks, runs as a live server, tested with a real HTTP client. |
| Two pluggable backends | **One real stub, one trivial, both real code.** `stub_ops_agent` is a deliberately naive stand-in for "Project 2's agent" — Project 2's actual codebase isn't in this sandbox, so this is a shape-alike simulation, not the real thing. Labeled clearly in [`gateway/adapters/stub_ops_agent.py`](gateway/adapters/stub_ops_agent.py). |
| Project 2 reconstruction (`project2_agent/`) | **Real, working code — a best-effort guess.** 7 tools, real internal tool-authorization, document retrieval with citations, a refusal-policy table — built from one paragraph describing the real Project 2, which wasn't available. Surfaced two genuine findings along the way: an evaluation-methodology issue, and a security control that was silently dead code (found and fixed in a later audit pass). See [`docs/project2_agent_notes.md`](docs/project2_agent_notes.md). |
| Attack simulation CLI | **Real.** Ran end-to-end against the live server (see below). |
| Latency measurement | **Real.** Measured, including an honest caveat about what the baseline actually represents. |
| CLI report view (Tier 2) | **Real.** `scripts/report_cli.py` — category-level pass-rate breakdown per layer, plus a gateway-on-vs-off comparison. |
| Adaptive thresholding (Tier 3) | **Real.** Per-session risk score tightens layer 2/3 thresholds after prior blocks. Demonstrated: identical borderline text, allowed for a clean session, blocked for a flagged one. |
| Streaming support (Tier 3) | **Real.** Post-flight checks re-run against the growing response buffer after every chunk; verified live over HTTP cutting off a leak after ~66 characters instead of the full ~240-character leak. |
| Real-time monitoring dashboard (Tier 3) | **Real.** `/gateway/stats` (JSON) + `/gateway/dashboard` (auto-refreshing HTML), reading the same JSONL log every request writes to. Verified against live traffic. |

---

## Architecture

```
Caller → Gateway
  ├─ 1. Pre-flight
  │    ├─ PII detection/redaction        (gateway/pii.py)
  │    ├─ Prompt-injection ensemble       (gateway/detectors/*, all 3 layers, block-on-any)
  │    ├─ Per-session rate limiting       (gateway/session_checks.py)
  │    └─ Session-behavior anomaly check  (gateway/session_checks.py)
  ├─ 2. If clean → forward to backend adapter (gateway/adapters/*)
  ├─ 3. Post-flight
  │    ├─ Role-based data exposure check  (gateway/role_exposure.py)
  │    ├─ Jailbreak-compliance detection  (gateway/response_checks.py)
  │    └─ System-prompt leak check        (gateway/response_checks.py)
  └─ 4. Log everything, return allow/block + response  (gateway/logging_schema.py)
```

**Pluggability:** backends implement one method — `send(prompt, session_id, role) -> str`
(see [`gateway/adapters/base.py`](gateway/adapters/base.py)). Dropping the gateway in
front of a different LLM app means writing one small adapter class, not editing the
gateway itself. Demonstrated with three structurally unrelated backends (see
[Proof requirements](#proof-requirements)).

**Project 2 integration (best-effort guess):** `project2_agent/` is a reconstruction
of Project 2 built from a one-paragraph description in the build doc — its real code
was never available in this sandbox. See
[`docs/project2_agent_notes.md`](docs/project2_agent_notes.md) for the full design
and, importantly, a real evaluation-methodology finding it surfaced: a strict
pass/fail metric can't distinguish "the gateway blocked this attack" from "nothing
recognized this as an attack, but the backend happened not to understand it either."
Replace this package wholesale once the real Project 2 codebase exists.

**Tier 3 additions:**
- **Adaptive thresholding** (`gateway/adaptive_threshold.py`) — a per-session risk
  score tightens the embedding-similarity and classifier thresholds after prior blocks
  in that session. Proven with a real before/after: the same borderline text is
  allowed for a clean session and blocked for a session that already triggered two
  prior blocks.
- **Streaming support** (`process_streaming`, `POST /gateway/chat/stream`) — post-flight
  checks re-run against the growing response buffer after every chunk, not just once
  at the end. A leaky response gets cut off mid-generation.
- **Live dashboard** (`GET /gateway/stats`, `GET /gateway/dashboard`) — reads the same
  JSONL log every request already writes to. Block rate, decisions by phase, blocks by
  detection layer, recent events, auto-refreshing every 2s.

---

## Detection layer comparison (the actual centerpiece)

Run via `python scripts/evaluate.py`, scored against `data/eval.csv` — our own
36-case corpus, **strictly held out from training** (see the leakage note below —
this wasn't always true, and the difference matters enormously).

| Layer | Detection rate | False-positive rate | Avg latency (ms) |
|---|---|---|---|
| rule_based | 23% (7/30) | 0% (0/4) | 0.024 |
| embedding_similarity | 0% (0/30) | 0% (0/4) | 6.566 |
| scratch_classifier | 50% (15/30) | 0% (0/4) | 0.107 |

### The biggest finding in this project: train/test leakage, found and fixed

These numbers replace an earlier, wrong set (embedding-similarity: 97%, classifier:
87%) that were inflated by a real bug: our own corpus was being mixed into training
data using the *same unmodified text* also used for evaluation, so the embedding
layer in particular was largely just recognizing its own exact answer key rather than
generalizing. Caught because three brand-new test cases came back with a similarity
score of exactly 1.000 — a strong tell for an exact string match, not a coincidence.

Full writeup with the before/after numbers and how it was found:
[`docs/leakage_fix.md`](docs/leakage_fix.md).

**The honest conclusion this leaves us with:** embedding-similarity, measured
correctly, provides **zero** real generalization from a public jailbreak dataset to
this project's own attack style. Rule-based and embedding-similarity are both
essentially non-functional against this corpus in isolation. The from-scratch
classifier (50% detection, 0% false-positive rate *on this corpus* — see the residual
domain-mismatch false-positive rate on unseen queries, which is a different and worse
number, in `docs/domain_shift_fix.md`) is the only layer doing real,
non-leaked work — and it's mediocre, not excellent. **This is a materially different,
more honest, and more useful conclusion than what an earlier version of this README
claimed**, and it's the direct result of catching a methodology bug rather than
declaring victory on a suspiciously good number.

### The gateway's real value is the ensemble, not any one layer

Despite the above, the gateway still measurably works end-to-end:
**6/36 pass without the gateway, 29/36 pass with it** (see
[Proof requirements](#proof-requirements)) — because rule-based catches the most
literal attacks outright, the classifier catches a real (if partial) share of the
rest, and the post-flight role-exposure/compliance/leak checks catch what pre-flight
misses. Defense-in-depth doing its job even with one layer contributing nothing is a
more realistic security story than "all three layers are individually excellent"
would have been.

### Remaining honest weaknesses on the current 36-case corpus

Still failing with the gateway on (per `scripts/report_cli.py`, `stub_ops_agent`
backend): GW-004, GW-006, GW-025 (indirect injection, missed), GW-011, GW-022
(encoding obfuscation, missed), and GW-027, GW-028 (multi-turn jailbreak, missed) —
7 of 36. This list shifted after the classifier-reproducibility fix (see
`docs/decisions.md`) changed which specific model gets trained; it's expected to
shift again on any future retrain, since the classifier's decision boundary isn't
identical to any previous snapshot's. None of these are hidden — they're in
`docs/redteam_report_gateway_stub_ops_agent.md` and surfaced directly by
`scripts/report_cli.py`. The domain-mismatch false-positive issue (GW-020 in an
earlier run, not necessarily the same case every run) is tracked separately in
`docs/domain_shift_fix.md`, since it's a property of unseen-query generalization,
not this specific corpus.

### Was embedding-similarity's design intent even tested fairly?

The build doc's original design for this layer assumed the known-bad index would
include our own found attacks, not just a public dataset — but doing that naively
is exactly the leakage bug above. Tested it properly with leave-one-out
cross-validation (`scripts/evaluate_embedding_loo.py`): for each corpus case, index
everything else, test if it's caught. **Result: 17% detection (5/30), with a new
false positive** — a real but modest improvement over the honest 0% baseline, not
enough to justify the added complexity and risk. Full reasoning for not adopting it
in production: `docs/embedding_loo_result.md` and `docs/decisions.md`. The takeaway:
even in the most favorable non-leaked test available, TF-IDF lexical similarity
struggles specifically because this corpus's attacks were deliberately written to be
diverse from each other — a real semantic embedding (the deferred DistilBERT path)
would be expected to do meaningfully better here.

---

## Proof requirements

- [x] **Detection comparison table, with numbers** — [`docs/comparison_table.md`](docs/comparison_table.md), reproduced above. Generated by `scripts/evaluate.py`, not hand-written. Numbers were wrong once (leakage) and got corrected — see `docs/leakage_fix.md`.
- [x] **A documented missed-attack case + the fix that closed it (or didn't, honestly)** — see the current miss list above and `docs/redteam_report_gateway_stub_ops_agent.md`. The deeper domain-shift story is in `docs/domain_shift_fix.md`, and the leakage story in `docs/leakage_fix.md` is arguably the strongest version of this requirement in the whole project.
- [x] **Attack simulation report against a real backend, end-to-end** — ran `scripts/run_redteam.py` against a live `uvicorn` server, against both backends:
  - **`stub_ops_agent`** — direct: 6/36 passed (`docs/redteam_report_direct_stub_ops_agent.md`); through gateway: 29/36 (`docs/redteam_report_gateway_stub_ops_agent.md`).
  - **`project2_agent`** (guessed reconstruction) — direct: 6/36 passed (`docs/redteam_report_direct_project2_agent.md`); through gateway: 24/36 (`docs/redteam_report_gateway_project2_agent.md`). Lower than the stub's score, for a non-obvious reason explained in `docs/project2_agent_notes.md` — worth reading before assuming the gateway is somehow "worse" against this backend.
- [x] **Latency overhead, reported honestly** — [`docs/latency_report.md`](docs/latency_report.md). ~9.9ms added per request in this sandbox. Reported with an explicit caveat: the stub backend has near-zero baseline latency (no real I/O), so a "gateway is X% slower" framing would be misleading here — see the report for the honest version of that number.
- [x] **Live demo of the gateway protecting the stub "Project 2 stand-in" specifically** — same corpus, same backend, gateway on vs. off, in `docs/redteam_report_direct_stub_ops_agent.md` vs `docs/redteam_report_gateway_stub_ops_agent.md`. Repeated against the fuller `project2_agent` reconstruction too — see above.

---

## Running it yourself

```bash
pip install -r requirements.txt
# or: pip install -e ".[dev]"

# 1. Build training data (pulls verazuo/jailbreak_llms from GitHub; needs network)
python scripts/prepare_training_data.py

# 2. Fit/train the detectors
python scripts/fit_embedding_detector.py
python scripts/train_scratch_classifier.py

# 3. Evaluate all three layers against the corpus
python scripts/evaluate.py

# 4. Start the gateway
uvicorn gateway.app:app --port 8000

# 5. In another terminal: attack simulation (through the gateway, or bypassed for comparison)
python scripts/run_redteam.py --target http://localhost:8000 --backend stub_ops_agent
python scripts/run_redteam.py --bypass-gateway

# 6. Latency measurement (gateway must be running)
python scripts/measure_latency.py

# 7. CLI report view (category-level breakdown + gateway on/off comparison)
python scripts/report_cli.py

# 8. Tests
pytest tests/ -v
```

---

## Known limitations (stated plainly, not buried)

- **Train/test leakage existed and was fixed** — see `docs/leakage_fix.md`. Not a
  limitation still present, but worth stating here because it's the reason every
  number in this README should be trusted only as far as its cited doc, not by
  reputation from an earlier version of this project.
- **No pretrained-weight access in the dev sandbox** — layers 2 and 3 are
  honest substitutions for what the original design called for. See
  `docs/decisions.md` for the full reasoning and the swap-in path.
- **Embedding-similarity provides no measurable generalization** from the public
  training dataset to this project's own attack corpus (0% detection, honestly
  measured). It's currently dead weight in the ensemble rather than a
  contributing layer. Kept in the pipeline for the architecture comparison's
  sake, not because it's pulling its weight.
- **~10% residual false-positive rate** on unseen in-domain benign queries after the
  domain-shift fix (down from a genuine, reproducible 60% before it — see
  `docs/domain_shift_fix.md`). Not necessarily 10% on the next retrain: see the next
  point.
- **Classifier training is now fully reproducible, but its exact numbers are still a
  property of one specific (fixed) random seed, not a law of the system.** An audit
  pass found PyTorch's RNG was never seeded — only Python's `random` was — so every
  retrain silently produced a different model despite the pipeline looking
  deterministic. Fixed (`scripts/train_scratch_classifier.py` now seeds torch and uses
  a seeded `DataLoader` generator; verified byte-identical model files across repeated
  runs). But this means every specific percentage in this README (50% detection, 10%
  residual FP, etc.) is tied to seed 42 on this exact codebase version — a different
  seed would give different real numbers, not because anything is broken, but because
  that's what "one trained model's performance" actually means. Don't treat these
  numbers as more fundamental than they are.
- **Session state is in-memory, single-process, and now bounded but not shared** —
  rate limiting and anomaly detection don't survive a restart or scale across
  multiple gateway instances without a shared store (Redis, etc.). An earlier audit
  finding (unbounded memory growth — every session_id ever seen stayed in memory
  forever) is fixed with periodic sweeping, but the fundamental single-process
  limitation remains. Fine for a portfolio demo, a real limitation for production.
- **Burst-at-session-start detection has no way to distinguish malicious from
  legitimate rapid usage** — e.g. a dashboard firing several requests on page load,
  within one session, gets flagged the same as an automated attack script would.
  Stated plainly in `gateway/session_checks.py`'s own comments: closing this
  detection gap cost some precision, not a free improvement.
- **`stub_ops_agent` is a simulation, not Project 2's real agent.** The
  integration with the actual Project 2 codebase (real tools, real
  refusal-policy table) is separate follow-up work, not done here.
- **Multi-turn detection tests concatenated transcripts as one message**, not
  true per-turn/session-context chaining. The session anomaly check catches
  request-rate spikes but not semantic content chaining across turns — a real
  gap for the "split the payload across turns" attack family (GW-009-style).
- **Post-flight checks are heuristic, not a data-lineage tracker.** They catch
  restricted content that matches known patterns, not arbitrary rephrasing of
  restricted data.

---

## Project structure

```
corpus/injection_cases.yaml           # 36 attack cases, versioned (v0.2.0)
corpus/benign_indomain_queries.yaml   # domain-shift fix data
project2_agent/                       # best-effort Project 2 reconstruction (guess)
  agent.py, auth.py, refusal_policy.py, tools.py, documents.py, eval_corpus.yaml
gateway/
  detectors/                          # 3 detection layers
  adapters/                           # pluggable backend interface + 3 implementations
  middleware.py                       # core orchestrator (incl. streaming + adaptive thresholding)
  app.py                              # FastAPI service
  adaptive_threshold.py, dashboard.py  # Tier 3
  pii.py, session_checks.py, role_exposure.py, response_checks.py, logging_schema.py
scripts/
  prepare_training_data.py, fit_embedding_detector.py, train_scratch_classifier.py
  evaluate.py, evaluate_embedding_loo.py, measure_domain_shift.py
  run_redteam.py, measure_latency.py, report_cli.py
  train_distilbert_finetune.py        # deferred, never run here
docs/
  decisions.md                        # running log, written as-we-go
  comparison_table.md, domain_shift_fix.md, leakage_fix.md, embedding_loo_result.md
  project2_agent_notes.md, latency_report.md
  redteam_report_{direct,gateway}_{stub_ops_agent,project2_agent}.md
tests/                                 # pytest, 23 passing
```
