# Detection layers: history, ablations and corrections

> Moved out of the README in Phase 7. Written incrementally during the build: numbers and status here may be older than the README, whose headline tables are generated from the current result files (`scripts/render_readme_headline.py`). Kept because the reasoning and the corrections are the point.

## Detection layer comparison (the actual centerpiece)

Run via `python scripts/evaluate.py`, scored against `corpus/injection_cases.yaml` — our own
100-case corpus (expanded: 36 → 72 on 2026-09-12, 72 → 100 on 2026-09-15;
see [`docs/corpus_expansion_result.md`](corpus_expansion_result.md)),
**strictly held out from training** (see the leakage note below — this wasn't
always true, and the difference matters enormously).

| Layer | Detection rate | False-positive rate | Avg latency (ms) |
|---|---|---|---|
| rule_based | 27% (21/78) | 6% (1/17) | 0.262 |
| embedding_similarity (TF-IDF; opt-in ablation, **disabled by default since 2026-09-25**) | 0% (0/78) | 0% (0/17) | 23.643 |
| embedding_similarity_st (sentence-transformer, opt-in) | 23% (13/56)* | 0% (0/12)* | 47.443 |
| scratch_classifier (in production; retrained 2026-09-22, see below) | 38% (30/78) | 12% (2/17) | 0.106 |
| distilbert_finetuned (comparison only) | 52% (29/56)* | 25% (3/12)* | 364.5† |

\* measured on 72-case corpus; not re-run on expanded corpus — see [`docs/comparison_table.md`](comparison_table.md).
† single-inference CPU timing, varies run-to-run.

**Corpus composition (100 cases):** 78 block + 5 ambiguous + 17 benign — expanded:
36→72 on 2026-09-12, 72→100 on 2026-09-15, adding underrepresented attack vectors
and tripling negative-control coverage. See [`docs/corpus_expansion_result.md`](corpus_expansion_result.md).
26 of the 100 are labeled `origin: public_pattern` — each mapped to a specific
named technique and real-world citation (OWASP LLM01, the Shen et al. 2024
jailbreak taxonomy, Unicode bidi-override CVEs, etc.), not just a label:
[`docs/corpus-references.md`](corpus-references.md). The rest are
`self_devised`, invented for this project rather than sourced.

### Per-category breakdown (100-case corpus, attack cases only)

`scripts/evaluate.py` now reports per-category detection rates — a more
honest view than the aggregate, because the five attack categories have very
different difficulty levels:

| Category (n attacks) | rule_based | embedding_similarity | scratch_classifier (retrained) |
|---|---|---|---|
| direct_injection (13) | 46% (6/13) | 0% (0/13) | **62% (8/13)** |
| encoding_obfuscation (20) | 15% (3/20) | 0% (0/20) | 45% (9/20) |
| indirect_injection (15) | 13% (2/15) | 0% (0/15) | 47% (7/15) |
| multi_turn_jailbreak (15) | 7% (1/15) | 0% (0/15) | 27% (4/15) |
| tool_scope_escalation (15) | 60% (9/15) | 0% (0/15) | 13% (2/15) |

The classifier handles direct injection best at 62%, while rule_based leads on
**tool_scope_escalation at 60%** — thanks to targeted patterns for social-engineering
delegation ("my director asked me to"), fake-authority claims ("scheduled internal
security test"), automated bulk-export requests, and cross-user tool impersonation.
These attack types don't use injection vocabulary; they exploit legitimate-looking
business framing, which is why a distinct pattern set was needed.
The full per-category table is in [`docs/comparison_table.md`](comparison_table.md).

### External benchmark (contamination-audited)

**Correction.** An earlier version of this section scored the detectors on a sample of jailbreak_llms and called it "independent of our training and eval data" (92% embedding / 97% classifier). That was wrong: `data/train.csv` is itself built from jailbreak_llms. `scripts/external_benchmark_v2.py` audits this by exact match (lowercased, whitespace-normalised): **422 of the 666 prompts (63%) are verbatim in the training positives**, and 93 of the 150 in the old sample. On those, the layers score 100% (embedding) and 97% (classifier), which is memorisation. Near-duplicates are not detected by this check, so true contamination is at least this high.

**Before retraining (v1 classifier).** Results on data the detectors did not train on (raw output as of 2026-09-20; the current numbers are further below; [`reports/p3_external_benchmark_v2.json`](../reports/p3_external_benchmark_v2.json); Wilson 95% CIs in the JSON):

| Dataset | Layer | Detection (attacks) | False positives (benign) |
|---|---|---|---|
| jailbreak_llms, 244 prompts not found in training | rule_based | 15.6% | n/a |
| | embedding_similarity | 65.2% | n/a |
| | scratch_classifier | 92.6% | n/a |
| | any layer blocks | 94.7% | n/a |
| deepset/prompt-injections (cc-by-4.0, unrelated authors; 263 injections / 399 benign) | rule_based | **0.8%** | 0.0% |
| | embedding_similarity | 22.1% | 16.8% |
| | scratch_classifier | 49.4% | **39.8%** |
| | any layer blocks | 63.9% | **48.6%** |
| JailbreakBench benign behaviours (100 borderline-benign requests) | scratch_classifier | n/a | **25.0%** |
| | any layer blocks | n/a | **26.0%** |

**After retraining (2026-09-21).** The classifier was retrained on a much more diverse set (deepset train, gandalf, jackhhao, safe-guard, alpaca, dolly, plus short chat messages) with all evaluation sets held out, and now skips inputs shorter than 3 word tokens. Full method, ablation, and what did not improve: [`docs/retraining-flow.md`](retraining-flow.md); raw output: [`reports/p3_shipped_heldout.json`](../reports/p3_shipped_heldout.json). Ensemble = block if any layer blocks:

| Held-out set | v1 ensemble | Retrained ensemble | Note |
|---|---|---|---|
| JailbreakBench benign, false positives (n=100) | 26% | **10%** | never trained on |
| Short messages, false positives (n=40) | 22.5% | **2.5%** | |
| deepset test benign, false positives (n=56) | 55% | **25%** | same-source split: deepset train is now in training |
| jailbreak_llms not in training, detection (n=244) | 94.3% | 91.8% | small detection cost |
| deepset test, detection (n=60) | 78% | 61.7% | same-source split |
| Own corpus, detection (n=78) | 61.5% | **53.8%** | detection cost of in-domain benign training (config E) |
| **Own corpus, benign false positives (n=17)** | 23.5% | **17.6%** | **improved: 5→3 of 17 after adding in-domain procurement data (config E), interval 6-41%** |

The cleanest evidence is leave-one-source-out (train without a source, test on it): classifier ROC-AUC on deepset 0.56 to 0.71, on safe-guard 0.55 to 0.90, on jackhhao 0.91 to 0.94. Held-out splits of sources that are in training (safe-guard, jackhhao, gandalf: ~0.99 AUC) are same-distribution and overstate generalisation. Config E (adding ~170 in-domain procurement/ops benign examples) improved in-domain FP from 5→3 of 17 (29.4%→17.6%) at a detection cost: own-corpus ensemble detection dropped from 61.5% to 53.8%. Deepset FP rose slightly to 25%.

**Can recalibration fix it?** Tried, held-out: thresholds chosen on deepset's train split cut false positives to near zero only by collapsing detection (5% at 0% FP on deepset test; own-corpus detection 62% to 27%), because the raw classifier score has ROC-AUC just 0.61 there. Full step-by-step story, chart and table: [`docs/recalibration-flow.md`](recalibration-flow.md).

What this means, stated plainly:

- **Generalisation is much weaker than the earlier README claimed.** On a genuinely different injection dataset the whole ensemble catches about 64% while blocking about 49% of benign prompts; the classifier alone is close to a coin flip (49% detection at 40% false positives). The rule-based layer catches almost nothing there (2 of 263), because deepset's injections are short natural-language instructions rather than the patterns it encodes.
- **The false-positive rate is the biggest problem**, not detection. The README's "~10% residual false positives" was measured on hand-written in-domain benign queries and does not transfer: 25-40% on external benign sets. As deployed, this gateway would block a large share of legitimate traffic from these distributions.
- Caveats: deepset includes German text and some short, ambiguous labels; JailbreakBench's "benign" requests are deliberately borderline (they mirror harmful topics), so a high false-positive rate there is partly a harder test; the jailbreak_llms "clean" subset may still contain near-duplicates of training data, so its 92.6% is an upper bound on true generalisation.
- The "0% internal / 92% external" narrative for `embedding_similarity` in earlier versions is withdrawn. It scores 0% on our hand-written attacks, 65% on the clean jailbreak_llms subset (likely inflated by near-duplicates) and 22% on deepset.

Two of these rows are separate experiments run to actually test a hypothesis
this project had previously only stated:

`embedding_similarity_st` swaps TF-IDF for a real `all-MiniLM-L6-v2` embedding
on the *same* known-bad index, threshold independently swept (0.35 isn't
comparable across different similarity distributions). **Confirms TF-IDF's 0%
is an architecture ceiling, not a tuning problem** — a real embedding finds
signal TF-IDF structurally can't, non-leaked, from the same public dataset. Set
`EMBEDDING_BACKEND=sentence_transformer` (opt-in; code default is `tfidf` — set at the
source in `gateway/middleware.py`, also explicit in `render.yaml`). Kept off by default because
it is still the weakest real detector (23% vs. the classifier's 48%) at ~500x the classifier's
latency, and it would re-introduce torch into the serving path this project deliberately removed
(see below).
Full writeup: [`docs/sentence_transformer_similarity_result.md`](sentence_transformer_similarity_result.md).

### Retiring the dead layer, and trying to make the guard model servable (Phase 2)

The TF-IDF layer scores 0/78 on our own corpus, so it was ablated
([`docs/ensemble-ablation.md`](ensemble-ablation.md), raw JSON in `reports/`). Removing it leaves own-corpus results
unchanged (42/78 detected, 3/17 false positives), cuts deepset false positives from 14/56 to 6/56 at a cost of
8 fewer attacks caught, and takes the ensemble from 4.4 ms to 0.11 ms p50. Swapping in the fp32 sentence-transformer
instead was worse (JailbreakBench benign false positives 9% to 24%). **Negative result kept:** exporting the
ProtectAI guard model to ONNX is exact and 2.5x faster than PyTorch (771 MB RSS, still too big), while int8
quantization breaks it (own-corpus detection 81% to 10-12%; per-channel and feed-forward-only variants recover to
62-64% but not fully, and still use 534-612 MB). No variant both fits 512 MB and keeps its accuracy.

### L2 threshold sweep (scripts/threshold_sweep_l2.py)

Run `python scripts/threshold_sweep_l2.py` to reproduce — sweeps both backends
at thresholds 0.05–0.95 against the current 100-case corpus (78 attacks, 17 benign; regenerated 2026-09-20 -- an earlier version of this script read a stale `data/eval.csv` export instead of the YAML corpus and is now fixed):

| Backend | Best F1 | Threshold | Detection | FP rate | Max detection at 0% FP |
|---|---|---|---|---|---|
| TF-IDF | 0.869 | 0.05 | 93.6% (73/78) | 100% (17/17) | **20.5%** at t=0.15 |
| sentence_transformer | 0.902 | 0.05 | 100% (78/78) | 100% (17/17) | **20.5%** at t=0.45 |

**The key finding:** neither backend can achieve useful precision by threshold tuning alone. At the best F1 threshold (0.05), both block almost all attacks but also block every legitimate request — precision ~0.82 (0.82 = 78 attacks / 95 total at 100% flagged). At the only threshold where FP rate = 0%, both backends catch about 20.5% of attacks. This confirms that **Layer 2 (embedding similarity) is structurally a low-precision first-pass filter in front of the classifier, not a standalone detector** — its value is catching attacks the rule-based layer misses, at the cost of false positives the classifier then adjudicates. The 3-layer ensemble's defense-in-depth design is validated: no single layer is sufficient.

Per-category breakdown at t=0.05 (both backends): direct_injection and multi_turn_jailbreak 100%, indirect_injection 100%, tool_scope_escalation 100%, encoding_obfuscation 71% (TF-IDF) / 100% (sentence_transformer). The only category where sentence_transformer beats TF-IDF at the optimal threshold is encoding_obfuscation — the obfuscated text fragments enough that TF-IDF's term-frequency signal breaks down, while sentence_transformer's contextual embedding still recognizes the semantic intent.

`distilbert_finetuned` is a real fine-tuned `distilbert-base-uncased` run,
re-scored on the expanded corpus (`scripts/rescore_distilbert.py`, inference
only, no retraining needed), scored with the exact same methodology as every
other row. **Ties the from-scratch classifier within a few points on both
metrics, at 2-3 orders of magnitude the latency** — pretrained language
understanding bought nothing over a from-scratch model trained on the same
~2,000 rows, including on the domain-shift false-positive test
(`docs/domain_shift_fix.md`). Full writeup, training run details, and the raw
eval JSON: [`docs/distilbert_finetune_result.md`](distilbert_finetune_result.md).

### Paraphrase robustness & evasion hardening (scripts/paraphrase_robustness.py)

Run `python scripts/paraphrase_robustness.py` to reproduce — applies 4 surface transforms to all 83 attack cases (100-case corpus, expanded from 72) and measures per-layer detection rate with and without text normalization:

Regenerated 2026-09-20 on the 78 attack cases of the current corpus, with the served (TF-IDF) embedding backend and the raw detectors (no normalizer) unless stated. The earlier version of this script scored a stale CSV export, so the older numbers here (72-case corpus, sentence-transformer column) are replaced, not supplemented.

| Transform | rule_based | embedding (TF-IDF) | classifier | Notes |
|---|---|---|---|---|
| original | 26.9% | 0.0% | 48.7% | baseline |
| case_swap | 26.9% | 0.0% | 48.7% | no impact |
| space_insert (no normalizer) | 0.0% | 0.0% | 74.4% | rule_based fully evaded; classifier goes **up** (see below) |
| space_insert (with normalizer) | 28.2% | 0.0% | **44.9%** | rule_based restored; classifier drops |
| synonym_sub | 19.2% | 0.0% | 50.0% | minor drift for rule_based |

**A finding that contradicts an earlier claim in this README.** The previous version said the normalizer "fully restored" the classifier (9.6% to 55.3%). On the current corpus the un-normalized classifier scores *74.4%* on zero-width-space-inserted text, higher than its 48.7% baseline, and the normalizer brings it down to 44.9%. The likely reason (not separately verified) is that zero-width characters push text off the classifier's training distribution toward "attack-looking" inputs, so it blocks more, including things it would otherwise miss; that is an accident, not robustness, and it would also raise false positives on benign text containing such characters (not measured here). What the normalizer demonstrably does is restore the rule-based layer (0% to 28.2%). Treat the classifier's behaviour on obfuscated input as unreliable in both directions.

**Text normalizer (`gateway/text_normalizer.py`) — 5 layers:**
1. **Unicode NFC** — resolves composed/decomposed character forms
2. **Zero-width stripping** — removes U+200B (ZWSP), ZWNJ, ZWJ, BOM, and 8 related chars; restores the rule-based layer on space_insert (0% → 28.2%; see the finding above for the classifier)
3. **Homoglyph normalization** — Cyrillic/Greek lookalikes → ASCII (covers GW-012, GW-106)
4. **Encoding decoding** — base64 blob detection + decoding; URL percent-encoding; 0x hex; leet-speak digit substitution (covers GW-010, GW-011, GW-103)
5. **Whitespace collapse** — normalizes multiple spaces/tabs

The normalizer runs in the middleware pipeline after PII redaction, before all three detection layers, so every layer benefits simultaneously.

**Encoding obfuscation layer:** `_decode_base64_segments()` finds base64 blobs (≥20 chars), decodes them, and *appends* the decoded text — the original stays for logs and the decoded form goes to detectors. URL-encoded attacks (e.g. `%49%67%6e...`) are decoded inline. This is a deliberate append-not-replace design: partial decoding failures don't suppress detection of the original encoded form.

**Corpus expansion:** eval corpus grew from 72 → 100 cases via `scripts/expand_eval_corpus.py` — 48 new hand-written cases across all 5 categories, including 10 new encoding_obfuscation variants (base64, hex, URL-encoding, leet-speak, Cyrillic, math Unicode, Caesar cipher, reversed text). All new cases are distinct attack vectors, not rephrases of existing ones.

### Throughput and concurrency — measured, including two bottlenecks found and fixed

`scripts/measure_throughput.py` hits a live `uvicorn` process with a mixed
benign+attack payload set at concurrency 1/10/50.

**Primary bottleneck (GIL):** detection work is CPU-bound Python/numpy in a
thread pool — the GIL serializes threads, so more concurrency means more
waiting, not more throughput. Diagnosed and verified: `--workers 4` (separate
GILs) roughly doubles throughput at c=50. Remains the ceiling.

**Secondary bottleneck (logging, fixed):** `GatewayLogger` was calling
`open(path, "a")` on every single request, causing file-lock contention across
threads. Fixed: a queue-backed background writer thread moves all file I/O off
the hot path. Result: **+73% req/s at c=10** (21.1 → 36.6), +39% at c=50,
+20% at c=1 — measured on the same machine before/after the fix.

After fix, single worker:

| Concurrency | req/s | p50 |
|---|---|---|
| 1 | 31.7 | 32.7ms |
| 10 | 36.6 | 289ms |
| 50 | 31.2 | 1643ms |

Full writeup with before/after tables: [`docs/throughput_report.md`](throughput_report.md).

**In-process benchmark** (`scripts/benchmark_throughput.py`, no HTTP overhead, no
server process — direct function calls against the full detection pipeline):

| Concurrency | req/s | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|
| 1 | 52.9 | 26.4 | 28.5 | 30.7 |
| 10 | 132.9 | 85.9 | 126.9 | 146.2 |
| 50 | 122.4 | 135.8 | 283.9 | 302.6 |

The gap between the HTTP server numbers (~21-26 req/s) and the in-process numbers
(53 req/s at c=1) isolates the uvicorn/asyncio overhead from the detection cost itself.

### The biggest finding in this project: train/test leakage, found and fixed

These numbers replace an earlier, wrong set (embedding-similarity: 97%, classifier:
87%) that were inflated by a real bug: our own corpus was being mixed into training
data using the *same unmodified text* also used for evaluation, so the embedding
layer in particular was largely just recognizing its own exact answer key rather than
generalizing. Caught because three brand-new test cases came back with a similarity
score of exactly 1.000 — a strong tell for an exact string match, not a coincidence.

Full writeup with the before/after numbers and how it was found:
[`docs/leakage_fix.md`](leakage_fix.md).

**The honest conclusion this leaves us with:** embedding-similarity, measured
correctly, provides **zero** real generalization from a public jailbreak dataset to
this project's own attack style. Rule-based and embedding-similarity are both
essentially non-functional against this corpus in isolation. The from-scratch
classifier (38% detection, 12% false-positive rate on the current 100-case corpus, after the 2026-09-22 retrain — see the residual
domain-mismatch false-positive rate on unseen queries, which is a different and worse
number, in `docs/domain_shift_fix.md`) is the only layer doing real,
non-leaked work — and it's mediocre, not excellent. **This is a materially different,
more honest, and more useful conclusion than what an earlier version of this README
claimed**, and it's the direct result of catching a methodology bug rather than
declaring victory on a suspiciously good number.

### The gateway's real value is the ensemble, not any one layer

Despite the above, the gateway still measurably works end-to-end
(see [Proof requirements](project-notes.md#proof-requirements)) — rule-based catches the most
literal attacks outright, the classifier catches a real (if partial) share of the
rest, and the post-flight role-exposure/compliance/leak checks catch what pre-flight
misses. Defense-in-depth doing its job even with one layer contributing nothing is a
more realistic security story than "all three layers are individually excellent"
would have been.

### Remaining honest weaknesses on the current 100-case corpus

Current per-layer false positives: `rule_based` — GW-052; `scratch_classifier` — GW-019,
GW-078. Missed attacks: `scratch_classifier` misses 48/78 attack cases; the
ensemble (block-on-any) reduces this to 36/78 — mostly encoding obfuscation and
multi-turn jailbreak categories (see `docs/comparison_table.md` for the full miss list). A published guard model (see [the guard-model baseline](guard-baselines.md)) catches substantially more of these same misses (80.8% vs 53.8% on this corpus) at a similar false-positive rate.

The redteam reports (`docs/redteam_report_gateway_stub_ops_agent.md`) were regenerated
on 2026-09-22 against the 100-case corpus. This list will
shift on any future retrain since the classifier's decision boundary isn't identical
to any previous snapshot's — none of it is hidden, it's surfaced directly by
`scripts/report_cli.py` and the redteam reports. The domain-mismatch
false-positive issue (a different, non-corpus benign query set) is tracked
separately in `docs/domain_shift_fix.md`.

### Was embedding-similarity's design intent even tested fairly?

The build doc's original design for this layer assumed the known-bad index would
include our own found attacks, not just a public dataset — but doing that naively
is exactly the leakage bug above. Tested it properly with leave-one-out
cross-validation (`scripts/evaluate_embedding_loo.py`): for each corpus case, index
everything else, test if it's caught. **Result (72-case corpus, historical): 32% detection
(18/56), with a 33% false-positive rate (4/12)** — a real improvement in detection
over the honest 0% baseline, but the false-positive rate (measured properly now
that there are 12 negative controls instead of 4) makes the "not worth adopting"
call even clearer than the original 36-case result suggested. Full reasoning for
not adopting it in production: `docs/embedding_loo_result.md` and `docs/decisions.md`.
The takeaway:
even in the most favorable non-leaked test available, TF-IDF lexical similarity
struggles specifically because this corpus's attacks were deliberately written to be
diverse from each other. (The natural next question — would a real semantic
embedding do better — was tested directly, not just assumed: see
[`docs/distilbert_finetune_result.md`](distilbert_finetune_result.md).
Short answer: no, not on this data.)

---
