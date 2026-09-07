# Decisions Log — Project 3: LLM Security Gateway

Running log, written as decisions are made. Not reconstructed after the fact.

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
Path("/home/dev/jbllms/...")` — a path that only existed because I'd manually
downloaded the dataset once by hand early in this project, completely outside
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
