# Decisions Log — Project 3: LLM Security Gateway

Running log, written as decisions are made. Not reconstructed after the fact.

---

## 2026-09-18 — Found via a flaky test: the demo endpoint rebuilt every detector on every request

`tests/test_demo.py::test_demo_run_rate_limited_after_threshold` (5 rapid
`/gateway/demo/run` calls) passed in isolation at 129.7s for one test and
failed intermittently as part of the full suite -- slow enough to look like a
timing-sensitive flake, but the actual cause was a real, severe performance
bug: `gateway/demo.py::demo_run()` built a brand-new `GatewayMiddleware()`
on every single request instead of reusing `gateway.app`'s existing
module-level singleton (which `/gateway/chat` already correctly reuses).

This was cheap and invisible back when the default layer-2 backend was
TF-IDF (unpickling a small sklearn object). It stopped being cheap the
moment `EMBEDDING_BACKEND`'s default changed to `sentence_transformer`
(2026-09-12 -- see the embedding-backend entries above): every demo request
was now loading a real torch-backed sentence-transformer model from disk,
turning a millisecond detection call into a ~20-30 second one, five times
per test run. The 60-second rate-limit window in the test fixture made this
a genuine race once total wall-clock started approaching it, not just a slow
test.

**Fixed:** `demo_run()` now imports and reuses `gateway.app.middleware`
instead of constructing its own. Verified: `test_demo_run_rate_limited_after_threshold`
alone dropped from 129.7s to a share of an 82s four-test run, and passes
reliably (previously flaky) once real per-request latency is back to
milliseconds instead of tens of seconds. Reusing the singleton also makes
the demo's session/adaptive-threshold behavior match real `/gateway/chat`
traffic instead of an artificially fresh state on every call -- a
correctness improvement, not just a speed one.

---

## 2026-09-12 — Corpus expanded 36 → 72 cases; found two real false positives the old one couldn't

External review flagged the 36-case corpus, and specifically its 4 negative
controls, as too small a sample to trust a false-positive claim from. Rather
than argue it, tested it: added 36 new cases (GW-037–072, corpus v0.3.0),
tripling negative-control coverage (4 → 12) and covering technique families
not previously in the corpus (repetition-extraction, fictional-framing,
continuation attacks, foot-in-the-door scope creep, requester_id
identity-spoofing -- directly targeting the real dead-code auth bug from
`docs/project2_agent_notes.md` -- audit-log-bypass framing, three new
encoding schemes, combining-diacritic Unicode abuse).

Regenerated `data/eval.csv` from the corpus (`scripts/prepare_training_data.py`
-- zero corpus rows in training, per the leakage-fix rule) and re-ran
`scripts/evaluate.py`, both live redteam reports (`scripts/run_redteam.py`,
both backends, bypass and gateway modes), the LOO-CV embedding experiment, and
re-scored (not retrained) both the sentence-transformer backend and the
DistilBERT fine-tune against the new eval set. Every number this project
publishes about corpus-scored detection is now against the same 72-case set.

**Found two real false positives a 4-negative-control eval set was
structurally incapable of catching:**
1. `rule_based`'s `RB-013` (`base64[\s\-]?decode`) blocks a benign "please
   decode this" request -- it keys on the request shape, not the decoded
   content, and no prior negative control happened to be a decode request.
2. `scratch_classifier`'s real false-positive rate is **25% (3/12), not the
   0% (0/4) every prior version of this README reported.** Checked actual
   confidence scores rather than treating "false positive" as one bucket:
   two are borderline (0.52-0.53, a clean self-lookup and a benign
   ROT13-decode request), one is a more confident miss on "disregard" outside
   an override context (0.64).

Neither fixed in code this pass -- both are measurement findings (the true
rates were always this, just unmeasured with only 4 negative examples), not
regressions, and reflexively patching either without deciding the
precision/recall trade-off properly would repeat the exact mistake
`docs/domain_shift_fix.md` already documented once. Full write-up, per-case
numbers, and the updated live-server pass rates (stub_ops_agent: 16/72 direct
-> 50/72 gateway, down proportionally from 6/36 -> 32/36 because the new false
positives now correctly count against it): `docs/corpus_expansion_result.md`.

**Also found and fixed in passing:** `scripts/run_redteam.py` opened a new
`httpx.Client` per request instead of reusing one across the run -- ~2s of
pure connection-setup overhead per case on this machine (>70x the gateway's
actual measured per-request cost from `docs/throughput_report.md`). Fixed;
verified identical pass/fail results before and after, only latency changed.

`docs/comparison_table.md`, `docs/embedding_loo_result.md`,
`docs/sentence_transformer_similarity_result.md`,
`docs/distilbert_finetune_result.md`, README, and `HIGHLIGHTS.md` all
regenerated/updated against the 72-case numbers.

---

## 2026-09-11 — Removed torch from the serving path; full mode now fits Render's free tier

**The gap:** `GATEWAY_LITE=1` existed because layer 3 (the scratch classifier)
was served by `gateway/detectors/classifier.py`, which imports torch — a
~700MB-installed dependency that made the full 3-layer ensemble too heavy for
Render's 512MB free instance. The public demo has been running the ensemble
*minus* layer 3 ever since, the one layer independently measured as doing real,
non-leaked detection work (`docs/comparison_table.md`).

**Why this was fixable:** the trained model itself is tiny — an
`nn.Embedding(8000, 64)`, a `Linear(64, 32)`, and a `Linear(32, 1)` (see
`gateway/detectors/scratch_classifier_model.py`). Its forward pass is mean-pool
+ two matrix multiplies + a sigmoid. There was never an inference-time reason
this needed a full deep-learning framework — torch is genuinely needed for
*training* (autograd, the optimizer, the DataLoader), not for running the
already-trained weights.

**What was built:**
- `scripts/export_classifier_to_numpy.py` — loads the torch `state_dict`, dumps
  the five weight tensors to `models/scratch_classifier/weights.npz` (plain
  numpy, no torch needed to read it back). Run once now; wired into
  `scripts/train_scratch_classifier.py`'s end so every future retrain
  re-exports automatically instead of silently drifting out of sync.
- `gateway/detectors/text_encoding.py` — split the tokenizer/vocab/`encode()`
  logic out of `scratch_classifier_model.py` into a module with zero torch
  import. This mattered more than it looked: the numpy detector originally
  imported `encode`/`PAD_IDX` from `scratch_classifier_model.py`, which still
  `import torch`s at the top for the `nn.Module` class — so torch was getting
  pulled in anyway despite the new detector never touching it. Caught by
  actually checking `'torch' in sys.modules` after building the middleware in
  full mode, not by assuming the refactor worked.
- `gateway/detectors/classifier_numpy.py` — re-implements
  `ScratchClassifier.forward()` term-for-term in numpy (embedding lookup, masked
  mean pool, `relu(x @ W1.T + b1)`, `x @ W2.T + b2`, sigmoid at the call site).
  Same `DetectionResult`/detector interface as the torch version — a drop-in
  swap in `middleware.py`.
- **Correctness verified, not assumed:** `tests/test_classifier_numpy_parity.py`
  runs both the torch model and the numpy one over the full 36-case corpus plus
  15 in-domain benign queries. Decisions match 100%; probabilities agree to
  <1e-4 (float32-torch vs float64-numpy accumulation, not a bug). This is the
  same "don't trust a claimed-equivalent substitution without checking" standard
  the embedding-similarity honesty note and the leakage fix both apply.
- `gateway/middleware.py` now loads `ScratchClassifierDetectorNumpy` by default.
  `GATEWAY_LITE` is kept as a genuinely optional "run a smaller ensemble on
  purpose" toggle — it no longer does anything to solve a resource problem,
  because there isn't one anymore.
- `Dockerfile.render` / `requirements-render.txt` / `render.yaml` updated:
  `GATEWAY_LITE=0` (full ensemble) is now the free-tier default. The render
  image copies `vocab.json` + `weights.npz` (a few hundred KB), not `model.pt`
  or torch.

**Verified live in this environment (not just in tests):** built a
`GatewayMiddleware()` in full mode and confirmed `'torch' in sys.modules` is
`False` before and after processing both a blocked attack and an allowed
borderline request that only layer 3 catches — the numpy classifier fired
correctly (`scratch_classifier: blocked=True`) with no torch import anywhere in
the process.

**What this doesn't change:** the from-scratch classifier's actual detection
quality (50% on the corpus, the residual domain-shift false-positive rate) is
unchanged — this was a serving-cost fix, not a model-quality fix. Numbers in
`docs/comparison_table.md` still describe the same model; it's just cheaper to
run now.

---

## 2026-09-11 — DistilBERT fine-tune: network access re-checked

The original "sandbox blocks huggingface.co" finding (`docs/decisions.md`,
2026-09-05) was specific to that build environment, not a property of this
project. Re-checked from the current environment: `huggingface.co` responds
`200`. `download.pytorch.org` is still `403` (irrelevant here — torch is
already installed via pip, not fetched from that host).

Installed `transformers`+`datasets` and benchmarked a real training step before
committing to a run: `wc -l data/train.csv` initially looked like ~35.7k lines,
which would have meant a multi-hour CPU fine-tune -- but that count is raw
lines, not rows (payload text contains embedded newlines inside quoted CSV
fields). Parsed properly with `csv.DictReader`, it's 2,020 rows (1,000
positive / 1,020 negative), matching this script's own docstring estimate.
Caught by actually parsing the file instead of trusting a quick line count --
the same discipline as every other "check, don't assume" moment in this log.
At ~2s/step (batch 32, CPU, 20 threads, benchmarked directly), the real script
is a ~15-20 minute job, not a multi-hour one. See the follow-up entry for the
actual run and its results.

---

## 2026-09-12 — Tested real sentence-transformer embeddings for layer 2

Same reasoning as the DistilBERT entry below applied to the OTHER documented
substitution in this project: `gateway/detectors/embedding_similarity.py`
(TF-IDF) has said since 2026-09-05 that swapping in real sentence embeddings
was "a drop-in change... if this ever runs somewhere with model-hub access."
That access exists now. Tested it instead of continuing to let that sentence
sit unverified.

`scripts/evaluate_sentence_transformer_similarity.py`: `all-MiniLM-L6-v2`,
same known-bad index as TF-IDF (`data/train.csv` label==1, 1,000 rows),
threshold independently swept (0.30-0.70) rather than reusing TF-IDF's 0.35 —
a different embedding space's cosine similarities aren't the same numbers.

**Result: 23% detection (7/30) at 0% false positives (threshold 0.45), vs
TF-IDF's 0%.** Confirms TF-IDF's zero is a real architectural ceiling, not a
threshold-tuning failure — a semantic embedding, on the exact same reference
set, finds signal TF-IDF structurally cannot. Still the weakest real detector
in the ensemble (`scratch_classifier` gets 50% at 1/440th the latency), and it
would cost re-introducing torch to the serving path — the dependency the
2026-09-11 classifier work removed specifically to fit Render's free tier.

**Decision: built it as a real, working, OPT-IN backend
(`gateway/detectors/embedding_similarity_st.py`,
`EMBEDDING_BACKEND=sentence_transformer`), not adopted as the default.**
Verified end-to-end through `GatewayMiddleware` with the env var set — it
correctly loads, indexes, and blocks a paraphrase-style attack TF-IDF misses.
Full reasoning and the full threshold sweep:
[`docs/sentence_transformer_similarity_result.md`](sentence_transformer_similarity_result.md).
This is the same "measure the real trade-off, decide with the number in hand"
discipline `docs/embedding_loo_result.md` already established for a different
version of this same question — the difference this time is the improvement
is real and non-leaked (0% -> 23% from the public dataset alone), just still
not worth making the default.

---

## 2026-09-12 — Throughput benchmark: a real concurrency bottleneck, found and diagnosed

Built `scripts/measure_throughput.py` (live HTTP, real uvicorn, mixed
benign+attack payload set, concurrency 1/10/50) in response to a fair
criticism this project had no answer to: no throughput numbers existed
anywhere in this repo.

**Finding: the gateway does not scale with concurrency on a single worker.**
req/s stayed flat (~21-26) from concurrency 1 to 50, while p50 latency grew
almost exactly linearly with concurrency (38.7ms -> 405.0ms -> 1948.7ms) —
the signature of requests being serialized, not parallelized.

**Diagnosed, not just observed:** `/gateway/chat` is a synchronous `def`
route, so Starlette runs it in a thread pool — but the actual detection work
(TF-IDF cosine similarity, the numpy classifier) is CPU-bound Python/numpy,
which the GIL prevents from running in true parallel across those threads.
More concurrent requests just means more threads taking turns.

**Verified the diagnosis by testing the fix, not just asserting it:** reran
the identical benchmark with `uvicorn --workers 4` (separate processes, real
parallelism). Throughput roughly doubled at concurrency 50 (22.5 -> 47.2
req/s), p50 roughly halved (1948.7ms -> 924.1ms) — consistent with a GIL-bound
diagnosis. Not a clean 4x, though, which is reported honestly as an
unresolved second-order bottleneck (plausibly OS thread-pool scheduling, or
contention on the shared JSONL log across processes) rather than rounded up to
"basically fixed."

**Not fixed in code this session** — filed as a documented, measured
limitation with a stated production path (`--workers N`, or moving detection
off the request thread pool entirely) rather than either hidden or patched
half-carefully under time pressure. Full write-up:
[`docs/throughput_report.md`](throughput_report.md).

---

## 2026-09-11 — DistilBERT fine-tune: ran it. The hypothesis didn't hold.

Ran `scripts/train_distilbert_finetune.py` for real: `distilbert-base-uncased`,
3 epochs, batch 32, same train/eval split and scoring methodology as
`scripts/evaluate.py`. Took ~63 minutes wall-clock (longer than the ~15-20 min
benchmark estimate — one checkpoint save between steps 112-113 stalled for
~33 minutes for a reason not diagnosed; noted rather than quietly excluded from
the total).

**Result: exact tie with `scratch_classifier`** — 50% detection (15/30), 0%
false-positive rate (0/4) on the standard corpus. Also ran it against the
domain-shift held-out benign set from `docs/domain_shift_fix.md`
(`scripts/measure_distilbert_domain_shift.py`, new): **1/10 (10%)** false
positives — the same rate, on the same query, as the scratch classifier.

This directly tests (not just repeats) the hypothesis this script's docstring
carried since 2026-09-05: "a real DistilBERT fine-tune should meaningfully
outperform the from-scratch classifier... because pretrained language
understanding generalizes better." **It didn't.** Identical accuracy, identical
domain-shift generalization, at ~325x the latency (34.9ms vs 0.11ms/request).
The missed-case sets aren't even identical (11 of 15 overlap, 4 differ each
way) — two different failure patterns landing on the same aggregate number, not
the same model twice.

Plausible reasons (reasoning, not a second unverified claim): 2,020 training
rows may just not be enough for either architecture to pull ahead, and/or this
corpus's attacks being deliberately lexically diverse from each other (see the
LOO-CV finding above) may resist a transformer's attention the same way it
resisted TF-IDF. 3 epochs at this learning rate is also an untuned recipe, not
an exhaustively searched one.

**Consequence:** no change to production. `gateway/detectors/classifier_numpy.py`
(the from-scratch classifier, served torch-free — see the entry above) remains
the right choice on every axis this comparison measured. What this closes is
the "hypothesis, not a result" caveat that sat in this repo for weeks — it's
now a measured result, and the measured result is "no meaningful difference,"
which is a more useful thing to know than an untested "presumably better."

Full write-up: [`docs/distilbert_finetune_result.md`](distilbert_finetune_result.md).
`docs/comparison_table.md` has the 4th row. The fine-tuned checkpoint (~2.5GB
across 3 epoch checkpoints + final) is gitignored (`models/distilbert_finetuned/`)
-- not part of the serving path, regenerable by re-running the script, and
several orders of magnitude past what's reasonable to commit for a result
already captured in `docs/`.

---

## 2026-09-07 — Cross-service connectivity

All three portfolio services are on Render. Made the P3 -> P2 link actually work
on the free tier and made connectivity observable.

- **`operations-assistant` exposes a public `POST /demo/chat`** — same agent as
  `/chat`, no API key, its own per-IP rate limit. The gateway adapter now takes
  `OPS_ASSISTANT_CHAT_PATH` (default `/chat`); `render.yaml` sets it to
  `/demo/chat`, so the deployed demo reaches the *real* Project 2 with **no
  secret**. A 401 on `/chat` also auto-falls-back to `/demo/chat`.
- **`GET /gateway/connectivity`** — reports, per backend, whether the gateway can
  reach it (HTTP backends expose `ping()` against the service's `/health`).
  Mirrors what `operations-assistant/health` does for `operations-performance`.
- **`_norm_path()`** tolerates an MSYS/Git-Bash-mangled path env value
  (`/demo/chat` -> `C:/Program Files/Git/demo/chat`) — only bites on Windows
  shells, but a real portability trap for local runs.
- **Verified live end-to-end:** a benign policy question through
  `llm-security-gateway-psax` -> `operations-assistant` `/demo/chat` returns a
  cited RAG answer, `allowed=True`, `upstream_error=False`. Contract audit of
  P2's tool client vs. P1's routes: all 8 paths match, auth is `X-API-Key` ==
  the other service's `API_KEY` on both hops.
- **Still on the user (Render dashboard):** set `OPS_PERFORMANCE_API_URL` +
  `OPS_PERFORMANCE_API_KEY` on the `operations-assistant` service so P2 can reach
  P1 (`ops_performance_api_reachable` is currently `false`, so P2's data/analytics
  tools fail and the agent burns its tool-call budget retrying). Code contract is
  already correct; this is pure env config.

---

## 2026-09-07 — Portfolio polish pass (post-deploy)

All three services are live on Render. This pass addresses gaps found by
reviewing the deployed state, not the code.

- **Upstream backend errors no longer render as "ALLOWED."** The
  `operations_assistant` HTTP adapter now prefixes every transport/HTTP failure
  string with `BACKEND_ERROR_PREFIX`; `/gateway/demo/run` detects it and returns
  a distinct `upstream_error` state (the demo panel shows "UPSTREAM ERROR", amber,
  not a green verdict). A 401 from the real Project 2 was previously shown as a
  successful gateway pass.
- **Demo endpoint abuse controls.** `/gateway/demo/run` now has a per-IP
  fixed-window rate limit (`DEMO_RATE_LIMIT`/`DEMO_RATE_WINDOW`, default 20/60s,
  `X-Forwarded-For` aware for Render's proxy) returning 429, plus an optional hard
  gate via `DEMO_API_KEY` + `X-Demo-Key`. It can reach an LLM-backed backend, so
  it shouldn't be open to unbounded scripted traffic.
- **Lite-mode is now stated on the demo page itself**, not just in docs — an amber
  banner when `GATEWAY_LITE=1` explaining layer 3 is off and `docker compose up`
  runs the full pipeline.
- **CI.** `.github/workflows/ci.yml` runs the suite (now 42 tests, +3 for the demo
  endpoint) on every push, plus a lite-mode import check. README badge added.
- **README restructured** to lead with the live-demo link, an SVG architecture
  diagram (`docs/architecture.svg`), and a 60-second quickstart; the "what's real
  vs. substituted" table moved down but kept. `HIGHLIGHTS.md` added — the three
  "made a number worse on purpose" stories pulled out of this log.

---

## 2026-09-07 — Portfolio-completion pass: git, live-run, demo page, deploy scaffolding

The project was code-complete but had never been version-controlled, run from a
clean environment, or deployed. This pass (phases agreed with the user) closes
that, without touching the security/ML substance.

**Phase 0 — version control.** `git init`, `main` branch. `.venv/` added to
`.gitignore` (caught it getting committed once, `git rm --cached`).

**Phase 1 — proven to run from clean.** Fresh venv on Python 3.10, `pip install
-r requirements.txt`, `pytest` → 38/38 pass. `requirements.txt` was un-pinned
(`>=`); now pinned to the resolved versions.
- **Real finding:** the committed TF-IDF model artifacts (`models/embedding_similarity/*.pkl`)
  were fit under scikit-learn 1.8 (Python 3.11+), but 1.8 requires Python ≥3.11 —
  on 3.10 the newest installable is 1.7.2, which loads the pickle with an
  `InconsistentVersionWarning`. Verified cosmetic: detector loads, scores are
  produced, all tests pass. Resolution: pin `scikit-learn>=1.7,<1.9`, target
  Python 3.12 for Docker/deploy (matches the artifact), document the 3.10 warning
  rather than retrain (a retrain under a different sklearn/torch would shift every
  documented number for no real gain).

**Phase 2 — real Project 2 adapter.** `gateway/adapters/operations_assistant_adapter.py`
talks to the real `operations-assistant` RAG service over HTTP (`POST /chat`,
`X-API-Key`), not by importing its package — it has much heavier deps (chromadb,
sentence-transformers, torch) and a real gateway sits in front of a service over
the network anyway. Registered in `app.py` only when `OPS_ASSISTANT_URL` is set.
The `project2_agent/` reconstruction stays as the zero-config default backend.
`docker-compose.trilogy.yml` wires gateway → operations-assistant → (host)
operations-performance for a genuine end-to-end run.

**Phase 3 — interactive demo.** `gateway/demo.py` — `GET /gateway/demo` runs the
*same prompt* bypassed vs. through the real `GatewayMiddleware`, side by side,
showing verdict / phase / firing layer / latency. Backend dropdown is populated
live from `/gateway/backends` so it adapts to lite mode and to whether the real
P2 is configured. Curated 7-case subset from the corpus (one per category + a
negative control). `middleware.py` now also includes the `per_layer` trace on the
allow path so "all layers passed" is visible, not just blocks.

**Phase 4 — deploy scaffolding (free tier only, user's constraint).**
- **Lite mode** (`GATEWAY_LITE=1`): skips the torch classifier entirely — no
  torch import, no model load — so the image fits Render's 512MB free tier.
  Ensemble runs rule_based + embedding_similarity + all pre/post-flight checks.
  New test `test_lite_mode_disables_classifier_but_still_blocks_and_allows`
  (39 tests now).
  **Honest cost, stated on the deploy page and here:** lite mode drops the one
  layer measured as doing real non-leaked work (50% detection — see
  `comparison_table.md`), so the *public* demo is the ensemble minus layer 3.
  Full pipeline = `docker compose up`.
- `Dockerfile` (full, Python 3.12) + `Dockerfile.render` (slim, no torch, copies
  only runtime paths) + `requirements-render.txt` + `render.yaml` Blueprint
  (no secrets) + `.dockerignore` + `DEPLOY.md`.
- The real Project 2 is **not** deployed: chromadb + sentence-transformers need
  ~2GB, i.e. a paid instance. Decided (with the user) to keep it as a local /
  docker-compose backend and let GitHub be where that integration is shown.

**Not done / deferred:** actually building the Docker images (no Docker in this
environment — user is installing Docker Desktop and will run
`docker compose up --build`); the actual Render deploy (needs the user's GitHub
push + dashboard); DistilBERT still never run (unchanged).

---

## 2026-09-05 — Corpus: build from scratch, do not wait on Project 2

**Decision:** Project 3's attack corpus (`corpus/injection_cases.yaml`) is built
independently, from zero, rather than treated as an extension of Project 2's red-team
corpus.

**Why:** Project 2's red-team corpus was discussed but never actually extracted into a
saved file — it doesn't exist as a retrievable artifact. Waiting on it would block
Project 3 indefinitely on something outside this project's control, and fabricating
placeholder cases "as if" they came from Project 2 would misrepresent provenance later
when the real corpus surfaces. Structure is intentionally identical to Project 2's
planned format (id/category/vector/payload/expected_behavior/observed_behavior/status/
notes) specifically so the two can be merged with a concatenation + ID-renumber later,
not a rewrite.

**Status:** Done. 20 cases in `corpus/injection_cases.yaml` v0.1.0.
- Categories: direct_injection (4), indirect_injection (4), multi_turn_jailbreak (3),
  encoding_obfuscation (5), tool_scope_escalation (4).
- Origin: 14 self_devised, 6 public_pattern-inspired (each labeled per-case).
- Includes 2 explicit negative controls (GW-019, GW-020) and 1 deliberately ambiguous
  case (GW-018, expected_behavior: flag) — these exist specifically to measure
  false-positive rate later, not just detection rate. A corpus that's 100% "should
  block" cases can't tell you anything about over-triggering.

**Not yet done:** `observed_behavior` and `status` fields are all null — no detector
exists yet to run against the corpus. This is expected at this stage, not an oversight.

---

## 2026-09-05 — Classifier training data: hybrid approach (confirmed by user)

**Decision:** Fine-tuned classifier trains on a public prompt-injection dataset (bulk
volume) + our own 20-case corpus mixed in as additional positive examples, with our
corpus also serving as the primary held-out eval set. Reasoning given: this is the most
defensible story in an interview ("trained on a public baseline, validated against my
own hand-built red-team corpus") and matches how real detection systems are actually
built and reported, rather than either over-claiming full originality or under-claiming
by using zero self-built data.

**Status:** Confirmed. Not yet implemented — see network-access note below, which
affects exactly this decision.

## 2026-09-05 — Pluggability interface: thin Python adapter class (confirmed by user)

**Decision:** Backends are represented as small `BackendAdapter` subclasses implementing
a `send(prompt, session_id) -> response` interface, not a config/YAML mapping layer.
Reasoning given: honest about what pluggability looks like at this project's scale, and
easier to defend line-by-line in an interview than a generic config-mapping abstraction.

**Status:** Confirmed. Drives `gateway/adapters/` design, to be built next.

---

## 2026-09-05 — Public training dataset: verazuo/jailbreak_llms (via GitHub, not HF)

**Finding:** `huggingface.co` is blocked (403) in this sandbox. Checked further and
found the constraint is total, not HF-specific: `hf-mirror.com`, `objects.githubusercontent.com`,
and `download.pytorch.org` are also unreachable. Only pypi/npm/crates (packages) and
`github.com` / `codeload.github.com` / `raw.githubusercontent.com` (repo content) work.
**This means no pretrained model weights of any kind can be downloaded here** — not
just HF-hosted ones. Reported to user before proceeding (see below).

**Resolution for the dataset specifically:** found `verazuo/jailbreak_llms` — the
dataset behind the ACM CCS'24 paper "Do Anything Now" — hosted directly on GitHub
(MIT licensed), not gated behind HF. Pulled via `codeload.github.com` tarball.
Contains `jailbreak_prompts_2023_12_25.csv` (1,405 labeled jailbreak prompts) and
`regular_prompts_2023_12_25.csv` (13,735 labeled benign prompts), real in-the-wild data
from Reddit/Discord/websites, Dec 2022–Dec 2023. This is the "public dataset" half of
the hybrid classifier training-data decision.

**Attribution:** Shen et al., "Do Anything Now: Characterizing and Evaluating
In-The-Wild Jailbreak Prompts on Large Language Models," ACM CCS 2024. Used here for
defensive classifier training only, per the dataset's stated research intent.

---

## 2026-09-05 — No-pretrained-weights constraint: Option C (from-scratch now + DistilBERT script deferred)

**Decision (confirmed by user):** Since no pretrained weights (DistilBERT, GloVe,
sentence-transformers, spaCy vectors — anything) can be downloaded in this sandbox,
build layers 2 and 3 as fully working, from-scratch implementations now, get real
numbers from them in this session, and separately write a DistilBERT fine-tuning script
as a documented "upgrade path" for the user to run in an environment with model-hub
access. The DistilBERT script's results will be explicitly marked not-yet-run — never
presented as if they came from an execution that didn't happen.

## 2026-09-05 — Two real weaknesses found and documented (not patched away silently)

**Finding 1 — multi-turn corpus contamination (false positive in embedding layer).**
Manual smoke-test with a fresh benign query ("Can you help me understand our SLA
policy?") got blocked by the embedding-similarity layer. Root cause: our multi-turn
corpus cases (GW-007/008/009) store all conversation turns concatenated as one string,
and that string — including its benign opening turn — was indexed verbatim into the
known-bad reference set. Fix: `scripts/prepare_training_data.py` now extracts only the
final (trigger) turn for training/indexing purposes on `multi_turn_jailbreak` cases;
`eval.csv` still uses the full concatenated payload unchanged, since a real scan sees
the whole message. Re-ran fit + train + eval after the fix — no false positives on the
corpus, and results are cleaner overall (see docs/comparison_table.md history).

**Finding 2 — domain-mismatch false positives (the bigger one).** After fixing Finding
1, the *same* benign SLA query still got blocked — this time by the scratch classifier.
Manual probing showed a 60% false-positive rate on realistic ops-assistant queries the
classifier had never seen, despite a clean 0% FP rate on our own 20-case corpus eval.
Root cause: the classifier's training data (`verazuo/jailbreak_llms`) is general
ChatGPT/Reddit-style prompts, not business-assistant queries, and our corpus's eval set
only has 2 benign examples, neither representative of real deployment traffic. **A
narrow, attack-heavy eval set looking clean does not mean the false-positive rate is
actually low** — this is the single most important lesson from this project so far.

**Fix attempted:** added `corpus/benign_indomain_queries.yaml` (30 realistic ops queries,
20 train / 10 held-out eval) and retrained. Full before/after in
`docs/domain_shift_fix.md`. Result: FP rate on held-out in-domain queries dropped
60% -> 30% — real improvement, **not a full fix**. Reported honestly rather than
declared solved. There's also a real precision/recall trade-off from this fix: attack
detection rate on our corpus dropped 94% -> 82% (now also misses GW-005, GW-010, in
addition to GW-011) — adding benign training examples pulled the decision boundary in
a direction that cost some recall on attacks. This trade-off is the actual ML story for
this layer, more honest than either number in isolation.

**Not resolved:** 30% residual false-positive rate on unseen in-domain benign queries
is a real, acknowledged limitation of training a small from-scratch classifier on
domain-mismatched public data plus only 20 augmentation examples. Closing this
properly would need either substantially more in-domain benign training data, or the
deferred DistilBERT fine-tune path (pretrained language understanding generalizes
better from few examples than an embedding matrix trained from scratch) -- exactly the
kind of result a real fine-tune might improve on, which is worth calling out explicitly
if/when that script gets run somewhere with model-hub access.

## 2026-09-05 — Corpus expanded to 36 cases (v0.2.0)

Added GW-021 through GW-036 (16 new cases): zero-width/RTL-override Unicode tricks and
ROT13 (`encoding_obfuscation`); tool-call-result, markdown-title, and table-cell
injection (`indirect_injection`); planted-false-memory and rapport-building chains
(`multi_turn_jailbreak`); recurring-export requests, cross-tool chaining, and
authorized-test framing (`tool_scope_escalation`); code-block-spoofed and
red-team-framing injection (`direct_injection`); two more negative controls (GW-034,
and GW-035 which specifically closes a gap — `multi_turn_jailbreak` had zero benign
examples in v0.1.0); and a second ambiguous/flag case (GW-036). Full corpus header
with the version history lives at the top of `corpus/injection_cases.yaml` itself now,
not just here.

**Process note:** `scripts/evaluate.py`'s `yaml.dump()` call strips the file's comment
header on every run (comments aren't preserved by PyYAML), and I re-added it by hand
twice before finally fixing the root cause — `update_corpus_observed_behavior()` now
reads and re-prepends the header automatically. Should have been enough on the first
finding; wasn't. Logging it for the same reason everything else in this file gets
logged.

## 2026-09-05 — Train/test leakage found and fixed (biggest finding in the project)

While sanity-checking the new GW-021/022/023 Unicode-obfuscation cases, the embedding
detector returned a similarity of **exactly 1.000** on all three — a strong signal of
an exact string match, not genuine similarity. Investigated and confirmed: 30 of 36
corpus cases had their exact payload text present in `data/train.csv`, because
`load_our_corpus()` mixed our corpus into training (per the original hybrid decision)
using the *same unmodified text* also written to `eval.csv`. Every single-message case
leaked; only the six multi-turn cases were accidentally clean, as a side effect of the
earlier trigger-segment-extraction fix, not because leakage was being guarded against.

**Fix:** `load_our_corpus()` no longer returns any training rows. The corpus is now
strictly held-out eval data, contributing zero rows to training. Training comes only
from the public dataset and the in-domain benign queries. Verified zero leakage
programmatically before re-running anything.

**Impact — the real numbers, not the leaked ones:**

| Layer | Detection rate (leaked, WRONG) | Detection rate (honest) |
|---|---|---|
| rule_based | 23% | 23% (unaffected — not ML-based) |
| embedding_similarity | 97% | **0%** |
| scratch_classifier | 87% | 63% |

Embedding-similarity's headline number was almost entirely an artifact of testing the
detector against its own answer key. With the leak fixed, it detects **zero** of 36
corpus attacks — TF-IDF similarity against a general public jailbreak/Reddit dataset
does not generalize to a differently-styled, hand-written attack corpus at all. Full
writeup: `docs/leakage_fix.md`. Every comparison table, redteam report, and CLI report
in this project has been regenerated against the honest numbers; nothing upstream of
this fix should be trusted at face value anymore, including the original v0.1.0
94%/82% figures reported earlier in this log.

**What still holds up:** the gateway's end-to-end value is still real and still strong
(6/36 pass without the gateway vs. 32/36 with it) — but that's the *ensemble* (rule-based
catching literal attacks, the classifier doing real if mediocre work, post-flight
role-exposure/compliance/leak checks catching what pre-flight misses) doing the work,
not any single layer being individually excellent. That's a more honest and, frankly,
more realistic story than the one this project was telling before.

---

## 2026-09-05 — Tested embedding-similarity's actual design intent via LOO-CV (decided not to adopt)

The build doc's original design for this layer was "embed your red-team corpus of
known injection attempts... generalizes to paraphrases of known attacks" — i.e. the
known-bad index was always meant to include our own found attacks, not just a public
dataset. The leakage fix above removed the corpus from the index entirely to get an
honest number, but that also meant the layer was never tested under its actual
intended design. Ran a proper test of that design without leaking: leave-one-out
cross-validation (`scripts/evaluate_embedding_loo.py`) — for each of the 36 corpus
cases, fit a fresh index on the public dataset plus every *other* corpus attack case
(never the one being tested), then check if it's caught.

**Result: 17% detection rate (5/30), with a new false positive (GW-035).** A real
improvement over the public-dataset-only 0%, but modest — and it introduces cost:
5 attacks caught only because a lexically-similar sibling attack happened to already
be in the corpus (GW-001 caught via similarity to other GW-00x direct-injection
phrasing, for instance), not because the layer understood the injection semantically.
25 of 30 attacks are missed even with every other corpus example available as
reference, because this corpus's cases were deliberately written to be diverse from
each other (an explicit design goal from day one — "invented variations... not copied
from a list"), and TF-IDF lexical overlap doesn't reward that diversity the way a
semantic embedding would.

**Decision: do not change production to index the corpus.** The gain (17%, with a new
false positive) doesn't justify the added complexity and false-positive risk, and the
from-scratch classifier already does the "learn from examples" job better (63%
detection via a real training loop) than a lexical lookup can. This result is kept as
a documented, honest limiting finding — see `docs/embedding_loo_result.md` — rather
than used to justify a change that would mostly just move the leakage problem to a
smaller, harder-to-notice place (5 cases quietly depending on their own near-duplicate
existing elsewhere in the corpus). It's also a clean argument for why the deferred
DistilBERT path (`scripts/train_distilbert_finetune.py`) matters: a real semantic
embedding should generalize across genuinely diverse attack phrasings in a way TF-IDF
demonstrably can't, even under the most favorable non-leaked test available.

---

## 2026-09-05 — Best-effort Project 2 reconstruction built (`project2_agent/`)

User asked to build "even for project 2, guess and build, we will fix accordingly."
Built a reconstruction from the build doc's one-paragraph description: 7 tools, a
document store with keyword-retrieval-with-citations, real internal
tool-authorization (`auth.py`), a refusal-policy table, and an eval corpus in the
described data/document/multi-step/adversarial shape. Every file's module docstring
states plainly this is a guess, not a recovery of real Project 2 code, since none of
it was available in this sandbox.

**Deliberate design split:** unlike `stub_ops_agent` (zero defenses, by design, to
maximize gateway-contribution visibility), this agent has real tool-authorization but
zero prompt-injection defense of its own. Verified directly: an employee's request for
the org-wide directory or audit log is refused by the agent's OWN auth with the
gateway fully bypassed; the same agent still leaks its system prompt when bypassed,
since that's not an authorization failure. This tests a more realistic and more
useful question than "does the gateway protect an undefended backend" — it tests
which attack categories the external layer actually adds value against once the
backend already handles some categories itself.

**Live results:** 6/36 direct, 28/36 through the gateway (vs. `stub_ops_agent`'s
32/36). Investigated why it's lower rather than assuming the gateway performs worse
here — checked the actual response text for two "FAIL" cases (GW-015, GW-017) and
found no leak occurred in either: the naive keyword router simply doesn't recognize
"database query tool" as matching any real tool, so it falls through to an unrelated
document snippet. This is a genuine evaluation-methodology finding, not a gateway
weakness: a strict pass/fail metric can't distinguish "attack correctly blocked" from
"nothing recognized this as an attack, and the backend's narrow capability happened
not to comply with it either." `stub_ops_agent`'s broader (if more naive) compliance
vulnerabilities give the gateway *more* genuine catches to take credit for — a
backend that's simply bad at understanding requests can look artificially safer under
this kind of test. Full writeup: `docs/project2_agent_notes.md`.

**Also generalized `scripts/run_redteam.py`** to support any registered backend in
both `--bypass-gateway` and through-gateway modes (was hardcoded to `stub_ops_agent`
in bypass mode) — needed this to run the comparison fairly across all three backends,
and it's a better-designed script for it regardless of this specific use.

---

## 2026-09-06 — Full audit pass: 4 real issues found and fixed

User asked to run tests and audit the project, mentioning issues, fixes, and lacks.
Systematic pass over the codebase (not just re-reading existing docs) found:

**1. Hardcoded sandbox-specific path (real portability bug).**
`scripts/prepare_training_data.py` hardcoded `JBLLMS_DIR =
Path("/home/dev/jbllms/...")` — a path that only existed because the dataset had
been downloaded by hand once early in this project, completely outside
the script itself. The README's claim that this script "pulls verazuo/jailbreak_llms
from GitHub" was **false** — it assumed the data already existed at that exact path.
Anyone else cloning this repo would hit `FileNotFoundError` immediately. **Fixed:**
added `download_jailbreak_llms()`, which downloads and caches the tarball into
`data/external/jailbreak_llms/` (repo-relative) on first run. Verified both the
download path and the cache-hit path work correctly.

**2. PyTorch RNG was never seeded (undermined the project's core premise).**
`scripts/train_scratch_classifier.py` seeded Python's `random` (for data shuffling)
but never called `torch.manual_seed()`. Every training run therefore produced a
genuinely different model — weight init and dropout were unseeded — despite the
pipeline *looking* deterministic (fixed `RANDOM_SEED = 42` constant, visible in the
code). Found because rerunning `scripts/measure_domain_shift.py` produced a 40% FP
rate where `docs/domain_shift_fix.md` documented 30% from an earlier run of the
supposedly-identical process. **Fixed:** added `torch.manual_seed()`,
`torch.cuda.manual_seed_all()`, and a seeded `torch.Generator()` for the training
DataLoader's shuffle. **Verified:** two independent training runs now produce
byte-identical `model.pt` files (diffed directly, not just compared metrics).

**Consequence:** the classifier's honest, now-reproducible detection rate is **50%**,
not the 63% reported earlier — a different number because it's a genuinely different
(but now pinned-down) model, not a regression. All downstream numbers (comparison
table, redteam reports, README) were regenerated to match.

**3. The domain-shift before/after demonstration was structurally broken.**
Once fix #2 made `prepare_training_data.py` unconditionally include the in-domain
benign fix, `scripts/measure_domain_shift.py`'s "before" measurement silently started
using the same (already-fixed) training data as "after" — rerunning it produced
byte-identical before/after results (both 10% FP), which should have been an obvious
red flag but would have been easy to miss without diffing the actual per-query
confidence values. **Fixed:** added `--exclude-indomain-benign` flag to
`prepare_training_data.py`, and restructured `measure_domain_shift.py` to explicitly
regenerate a genuine pre-fix training set for the "before" measurement rather than
assuming "whatever model currently exists" means "before." **Re-verified:** now shows
a real, reproducible 60% -> 10% (an even better result than the old, non-reproducible
"30%" — but reported because it's real, not because it's a better number).

**4. Stale hardcoded narrative text in a doc-generating script.**
`measure_domain_shift.py` had "our own 20-case attack corpus... only contains 2
benign examples" hardcoded directly into the f-string that generates
`docs/domain_shift_fix.md` — accurate when written (before the corpus expansion to 36
cases / 4 negative controls), silently wrong after. **Fixed:** these counts are now
computed from the corpus file at doc-generation time, not hardcoded.

**Also found, fixed without a full narrative (smaller/more mechanical):**
- `requirements.txt` and `pyproject.toml` declared `pandas` and `numpy` as
  dependencies; neither is imported anywhere in the codebase. Removed.
- No `.gitignore` existed. Real risk: `data/external/` (the downloaded dataset) is
  39MB and fully regenerable — committing it to a future git repo would be a real
  mistake. Added, along with excluding regenerated `data/train.csv`/`data/eval.csv`
  and runtime `logs/*.jsonl`. Trained model artifacts (~7MB) are intentionally NOT
  ignored, so the gateway runs immediately after a clone without retraining first.
- No `LICENSE` file. Added MIT, with a note on the corpus's own attribution.

**Test suite fallout from fix #2 (3 failures, all fixed):**
Retraining with the now-correct seed shifted the classifier's decision boundary,
breaking three tests that hardcoded specific phrases tied to the old model's exact
behavior — the same fragility pattern flagged twice already in this log (see the
Tier-3 adaptive-thresholding entries above). Rather than patch each one with yet
another magic phrase:
- `test_classifier_blocks_direct_injection`: switched from a hand-typed paraphrase to
  GW-001's exact corpus payload (tracked in `corpus/injection_cases.yaml`, known via
  `scripts/evaluate.py` to score reliably high) — more robust than a fresh string.
- `test_role_exposure_blocked_postflight`: found and verified a replacement phrase
  that still passes pre-flight cleanly under the new model.
- `test_adaptive_thresholding_tightens_for_risky_sessions`: **fixed properly this
  time** instead of finding a third magic phrase — now searches a pool of candidate
  phrases at test-run time for one that actually lands in the needed probability
  window against whatever model is currently loaded, and skips (with a clear reason)
  rather than failing confusingly if none do. This should survive future retrains
  without manual intervention.

**Also found and fixed while auditing `project2_agent`'s intent-routing regexes (the
last unaudited area named in the previous entry):**

- **Anomaly detector blind to bursts at session start.** `gateway/session_checks.py`'s
  ratio-based spike check compares a session's recent rate against its own historical
  rate — which doesn't exist yet for a brand-new session, so a 10-request burst fired
  immediately at session start went completely undetected (verified empirically: all
  10 requests allowed). Fixed with an absolute burst check for the first
  `ANOMALY_WINDOW_SECONDS`. **Cost stated plainly, not hidden:** this also flags
  legitimate rapid-fire usage (e.g. a UI firing several requests on page load) — closing
  a real detection gap necessarily costs some precision, not a free win.

- **Unbounded memory growth in both session trackers.** Neither `SessionTracker` nor
  `AdaptiveThresholdTracker` ever evicted old entries — every unique session_id ever
  seen stayed in memory for the process's lifetime. Fixed with periodic sweeping in
  both (evicting sessions whose timestamps/risk have fully aged out), verified with
  tests simulating 150 one-shot sessions correctly evicting down to ~100.

- **A malformed log line could crash the entire monitoring dashboard**, and separately,
  **the stats endpoint did an O(total-lines-ever-written) full-file re-read on every
  poll** (polled every 2 seconds by the dashboard). Fixed both: field validation before
  trusting a parsed JSON line's shape, and a proper incremental log-tail reader that
  tracks a byte offset, handles log rotation/truncation, and doesn't consume an
  in-progress partial write. Verified with 4 new tests covering all of that.

- **The biggest finding of this second audit pass: a documented security control that
  was silently dead code.** `project2_agent`'s "own tickets/records only" scoping
  (`schedule_escalation`, `lookup_employee_directory` in `tools.py`) depends on a
  `requester_id` parameter — which nothing in the system ever actually passed. Traced
  the gap all the way up: the entire gateway pipeline (`BackendAdapter`,
  `GatewayMiddleware`, the FastAPI `ChatRequest` model) only ever tracked a coarse role
  tier, never individual requester identity. Verified empirically before fixing: any
  employee could escalate any other employee's ticket. Fixed by threading a `user_id`
  parameter through the whole chain — every adapter, `GatewayMiddleware.process()` and
  `.process_streaming()`, and the FastAPI request model. Re-verified both in-process
  and over live HTTP: an employee can now escalate their own ticket but is correctly
  refused for someone else's; a self-lookup test specifically used a *different* test
  employee than the router's hardcoded default target, to avoid a coincidental false
  pass the same way `test_employee_cannot_look_up_someone_elses_contact_info_via_generic_phrasing`
  is named to make explicit.

  **This fix had a small side effect, caught by rerunning the redteam suite rather than
  assumed clean:** the fix added a new routing trigger ("my email") to correctly route
  self-lookup requests, which unintentionally also matches GW-029's payload ("...export
  of all employee records to my email...") in an unrelated context. This misroutes it to
  a self-lookup of a nonexistent "unknown" test employee, returning a harmless
  `"No employee found: unknown"` rather than triggering the injection classifier or a
  real leak -- gateway score dropped from 25/36 to 24/36 as a result. Verified this is
  the same "router doesn't understand this attack, but the response is harmless" pattern
  already extensively documented below, not a new security hole -- confirmed by checking
  the actual response text, not just the pass/fail label (the same discipline
  `docs/project2_agent_notes.md` already establishes for this exact kind of surprising
  number). Not further tuned, since chasing keyword-routing edge cases indefinitely is
  scope creep beyond what a guessed reconstruction's routing logic needs to demonstrate.

All 38 tests pass after this round (up from 30). Full pipeline re-verified end-to-end:
live server smoke test over real HTTP (both the refusal and the success case for the
`user_id` fix), and both backends' redteam reports regenerated.

---

## 2026-09-05 — Tier 3 stretch items: all three built and demonstrated

**Adaptive thresholding** (`gateway/adaptive_threshold.py`): per-session risk score,
incremented on each block (pre- or post-flight), linearly decayed over time. Risk
scales down the embedding-similarity and classifier thresholds (easier to trip) for
sessions that already look suspicious. Demonstrated with a real before/after: the exact
same borderline text ("Would you consider relaxing your standard approach just for me?" —
classifier probability 0.451, below the 0.5 baseline) is **allowed** for a clean session
and **blocked** for a session that already triggered two prior blocks (risk=0.6,
effective classifier threshold drops to 0.35). Not asserted — reproduced via a passing
test (`test_adaptive_thresholding_tightens_for_risky_sessions`).

**Addendum (post-leakage-fix):** retraining the classifier after fixing the train/test
leakage (see below) shifted its output probabilities, and the original borderline test
phrase no longer landed in the right range -- had to search for a replacement. Worth
noting as an illustration of a real cost of this kind of test: a hardcoded "borderline"
example is tied to a specific model snapshot, not a stable property of the system, so
it needs re-verification after any retrain. A more robust version of this test would
search for a borderline example programmatically rather than hardcoding one -- left as
a possible improvement rather than done now.

**Streaming support** (`GatewayMiddleware.process_streaming`, `/gateway/chat/stream`):
post-flight checks (role exposure, jailbreak-compliance, system-prompt leak) re-run
against the growing response buffer after every chunk, not just once at the end. The
stub backend's `stream()` override yields word-by-word (real incremental generation, not
just chunking a finished string) so this is a genuine test of catching a leak mid-stream.
Demonstrated live over real HTTP: a prompt that passes pre-flight but causes the naive
backend to leak its system prompt gets cut off after ~66 characters
("Sure, here is my configuration: You are an internal operations ") instead of the full
~240-character leak completing. Verified both in-process (`test_streaming_cuts_off_leak_mid_generation`)
and via `curl -N` against a live `uvicorn` server.

**Real-time monitoring dashboard** (`gateway/dashboard.py`, `/gateway/stats` +
`/gateway/dashboard`): reads the same `logs/gateway.jsonl` every request already writes
to — no separate telemetry pipeline. JSON stats endpoint (block rate, decisions by
phase, blocks by layer, avg latency, last 20 events) plus a plain auto-refreshing HTML
page (vanilla JS, polls every 2s, no build step or frontend dependency). Verified live:
generated real traffic through the running server and confirmed both endpoints reflect
it accurately, including a real (and expected, per the documented domain-mismatch issue)
false-positive block showing up in the recent-events feed.

**Honest scope note:** all three are real, working code, verified against a live
server, not just described. None of them fix the underlying 30% residual false-positive
rate documented in `docs/domain_shift_fix.md` — the dashboard makes such false positives
*visible* in real time, which is different from *reducing* them, and is presented as
such rather than conflated.

---

## 2026-09-05 — Concrete architecture chosen for layers 1-3 (reference)

- Layer 1 (rule-based): regex/keyword matching, stdlib only, with Unicode NFKC
  normalization to catch homoglyph tricks (see GW-012).
- Layer 2 (embedding similarity): TF-IDF vectors (scikit-learn) + cosine similarity
  against a known-bad set, instead of transformer sentence embeddings. This is a real
  but lighter-weight notion of "embedding" than the build doc implies — documented
  explicitly as a sandbox-driven substitution, not silently relabeled as the real thing.
- Layer 3 ("fine-tuned classifier" analog): a small PyTorch model — an embedding
  matrix trained from scratch (not fine-tuned from a pretrained checkpoint) over a
  vocabulary built from the training corpus, mean-pooled, into a 2-layer MLP head,
  trained with a real training loop (train/val split, BCE loss, early stopping). This
  keeps the "transferable ML skill" and "real precision/recall story" the build doc
  wants for this layer, without claiming a fine-tune that can't actually happen here.
  Labeled in the README as "trained from scratch" — explicitly not the DistilBERT
  fine-tune the build doc originally specified, with the swap-in script provided
  separately for later.
- Training data: `verazuo/jailbreak_llms` (bulk volume, real labeled positive/negative
  examples) + our own 20-case corpus mixed into training as additional positive/negative
  signal, with our corpus *also* serving as the primary held-out eval set for the
  comparison table (per the earlier hybrid decision).

## 2026-09-21: retrained the scratch classifier on diverse data; added a short-input guard

**Context.** A contamination audit showed the "independent" external benchmark overlapped the training set by 63%, and the honest external numbers showed 25-55% false positives. Threshold recalibration could not fix this because the raw classifier score had ROC-AUC ~0.6 on independent data (docs/recalibration-flow.md).

**Decision.** Retrain on deepset train, gandalf, jackhhao, safe-guard, alpaca, dolly and short chat messages (config D, seed 0), holding out every evaluation set (exact-match removal). Keep the v1 weights in models/scratch_classifier_v1. Add a guard so the classifier skips inputs shorter than 3 word tokens; mean-pooling makes 1-2 word inputs unreliable (v1 also scored "ok" 1.0), and only ~2 of ~1,280 held-out attacks are that short. The rule-based layer still inspects every input.

**Evidence and limits.** Leave-one-source-out AUC rose 0.56 to 0.71 (deepset), 0.55 to 0.90 (safe-guard); JailbreakBench benign false positives fell 26% to 7%. In-domain benign false positives did not improve (n=17), and jailbreak-style detection fell 94% to 91%. Numbers are 3-seed means with small held-out sets. Full write-up: docs/retraining-flow.md.

## 2026-09-23: added a guard-model baseline (protectai/deberta-v3-base-prompt-injection-v2)

**Context.** An external skills review named "no baseline against existing guard models" as the single biggest credibility gap in this project: building a detector from scratch invites the obvious "why not just use Prompt Guard / a HF guard model" question, and this project had never measured the answer.

**What was done.** Ran protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0, ungated) on the exact same held-out sets used for the classifier retrain (scripts/guard_model_baseline.py, reports/p3_guard_baseline.json). meta-llama/Llama-Prompt-Guard-2-86M is gated behind manual Meta approval and was not evaluated.

**Result, stated plainly.** On our own corpus the guard model detects far more attacks than our ensemble (80.8% vs 53.8%) at a similar false-positive rate — on this evidence, a team optimizing purely for detection quality on this exact corpus should have started with the guard model. On deepset the result flips (our ensemble 61.7% detection / 25% FPR vs guard 36.7% / 0%). The guard model is CPU-latency-heavy (13-650ms vs our ~4ms full ensemble) and a ~700MB dependency, which is exactly the torch-on-Render-512MB problem this project's numpy-classifier port was built to avoid, so it stays an offline comparison, not a deployed layer. Not tested: combining it as a 4th ensemble layer, which the numbers suggest could raise detection and lower false positives together.

## 2026-09-24: guard-baseline harness completed (Phase 1); serving unchanged

**Context.** The 2026-09-23 baseline was a one-off script with detection/FPR only. Phase 1 of the upgrade plan asked for a reproducible harness with ROC-AUC, latency, memory, license, and the combined configuration.

**What was done.** `scripts/baselines/run_guard_baselines.py` (optional extra `[baselines]`, never imported by `gateway/` or CI) replaces the earlier script. It adds ROC-AUC, p50 single-example latency, incremental RSS, weights size, license, and the "ours OR guard" configuration, and records models it cannot load as `not_evaluated` with the reason.

**Findings.** ProtectAI DeBERTa beats our ensemble on own-corpus detection (80.8% vs 53.8%) and is far more precise on deepset and JailbreakBench benign; our ensemble wins on deepset detection and jailbreak_llms (likely inflated by near-duplicates). The OR combination reaches 85.9% own-corpus detection but keeps our false positives. The guard model costs +858 MB RSS and 17.5x the p50 latency.

**Decision.** Keep serving the from-scratch ensemble solely because of the 512 MB free-tier constraint; state plainly that on detection quality the existing guard model is better on this corpus. Meta Prompt Guard 2 and Llama Guard were not evaluated (gated, no HF token). A precision-oriented combination (guard as the only learned layer plus rules) is deferred to Phase 2.

## 2026-09-25: Phase 2, TF-IDF layer removed from the default ensemble; guard model not made servable

**Context.** The TF-IDF similarity layer detects 0/78 of the project's own attacks. It was the most expensive layer (~4 ms of a 4.4 ms ensemble).

**Evidence.** Ablation (scripts/baselines/ensemble_ablation.py, docs/ensemble-ablation.md): removing it leaves own-corpus results identical (42/78, 3/17), cuts deepset false positives 14/56 to 6/56 while losing 8 detections, and takes p50 from 4.4 ms to 0.11 ms. Swapping in the fp32 sentence-transformer raised JailbreakBench benign false positives from 9% to 24%. Guard model to ONNX: fp32 exact (771 MB RSS), int8 breaks it (own-corpus detection 81% to 10-12%; per-channel and FFN-only recover to 62-64%; 534-612 MB RSS).

**Decision.** `EMBEDDING_BACKEND` defaults to `none` (layer 2 disabled); `tfidf` and `sentence_transformer` stay opt-in; unknown values raise instead of silently falling back. The guard model stays a reference baseline; nothing that fits 512 MB kept its accuracy. Red-team reports regenerated (through gateway: stub 71/100, project2 66/100). Not tried: quantization-aware fine-tuning, static quantization with calibration data, embedding-vocabulary pruning, Prompt Guard 2 22M (gated).

## 2026-09-25: Phase 3, action firewall (policy + taint + approvals + MCP proxy)

**Context.** The gateway inspected text only; an injection that passes the text layers becomes a tool call. The plan asked for an action-level control point.

**Decisions.** (1) Policy engine: a small YAML evaluator (default-deny, first matching rule, strict arguments, validated on load) rather than OPA/Rego or Cedar: OPA needs a separate server or binary and Cedar's bindings are a native dependency, against a torch-free 512 MB target; migration to Cedar is the documented path for larger policy sets. (2) Taint: string-overlap provenance on observable strings, trusted-wins, per-argument `deny`/`flag`; explicitly not CaMeL, and its evasions are pinned in tests and measured. (3) Approvals: SQLite (shared between the stdio proxy process and the web app), manager/admin only, separation of duties, expiry, pending cap, execution tracked separately, policy re-checked at execution time. (4) MCP proxy: stdlib stdio JSON-RPC filter; unknown protocol methods blocked, id-less `tools/call` dropped, non-object arguments rejected, reserved id prefix.

**Evidence.** 54-scenario corpus: 38 of 39 in-scope harmful scenarios stopped outright (28 policy, 10 taint), 1 held at high risk, 6 known evasions held for approval, 0 benign false blocks; 53 of 59 calls match ground truth (all mismatches are the known evasions). Text layers: 2 of 2 user-message attacks detected but 5 of 52 innocuous messages blocked; an earlier version of the evaluation credited those 5 false positives as detections and was corrected. Verified against P2's real MCP server (employee sees 7 of 9 tools). 142 new tests; full suite 221 passing.

**Found and fixed on the way.** Stored XSS in the dashboard (request-controlled fields in innerHTML); `Dockerfile.render` did not copy `config/`; unbounded memory/queue growth on unauthenticated endpoints; a clock-resolution-dependent test.

**Not done.** Principal/approver authentication, HTTP MCP transports, the user's message in MCP mode, multi-instance state, an independent red-team of the firewall (Phase 4).

## 2026-09-25: Phase 4, red-team with standard tools and an adaptive attacker

**Context.** The action firewall's corpus had the same author as the firewall, and the text layers had only been tested with the author's own attack set.

**Decisions.** (1) Use garak 0.16.0 and promptfoo 0.119.0 (pinned; 0.123.1 needs a newer Node than the machine has) against a shim that exposes one backend both directly and through the gateway, and count an attack as successful only if it was **not blocked and the detector fired**: garak's DAN detector treats the gateway's own "[BLOCKED ...]" text as a hit, which first made the gateway look as bad as no gateway. (2) An LLM attacker (Groq gpt-oss, free tier) with three victim modes, because a robust victim rarely emits the harmful call, so the firewall is barely exercised; the *compromised* mode removes the victim and lets the attacker choose the exact call. (3) A deterministic mutation attacker (74 calls) because the LLM attacker is quota-limited and rarely tries obfuscation. (4) Report structure: findings table with OWASP LLM 2025 and MITRE ATLAS IDs, severity, evidence, fix, retest; ATLAS IDs flagged as unverified.

**Results.** 12 weaknesses (6 fixed, 6 open) plus one measurement artefact; see `reports/redteam-2026-09.md`. Fixed: RT-01/02 rate-limit bypasses (per-IP limit, forwarded header ignored unless `TRUSTED_PROXY_HOPS`), RT-03 Unicode-tag smuggling (0 to 32 of 32 blocked), RT-04 zalgo, RT-07 dashboard stored XSS, RT-09 detection-normalised text was forwarded to the backend (now `sanitize()` removal-only). Open, pinned as `xfail(strict)`: RT-05 latent injection, RT-06 ROT13/Atbash/reversed, RT-08 a classifier false positive, RT-10 taint token-boundary bypass (new), RT-11 documented taint misses, RT-12 confidential data via a trusted tool. Action firewall: 0 of 39 policy-enforced mutations bypassed; 15 of 29 identifier mutations passed the taint check and were all held for approval, none executed.

**Not decided here.** The taint upgrade (compact-form matching, normaliser stage, embedding fallback) is queued, not done: the `KNOWN_MISSES` set in `tests/test_action_mutations.py` is the before/after measurement for it. ROT13-style decoding is not enabled because appending decoded gibberish to every message changes classifier inputs and needs a false-positive measurement first.

**Limits worth repeating.** Same-author test design (reduced, not removed); a 36% unusable-reply rate from the 20b attacker; the attacker model differed between runs because the 120b daily quota ran out; the raw JSON of the first robust run was deleted by mistake, so its figures come from the console summary; the public deployment was not scanned; the MCP transport layer was not attacked.
