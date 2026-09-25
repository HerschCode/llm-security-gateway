# Guard-model baselines (Phase 1)

**Question:** why build a detector from scratch when purpose-built guard models exist?
This measures it. One script, one table, raw JSON, negative results kept.

- Script: `python -X utf8 -m scripts.baselines.run_guard_baselines` (optional extra: `pip install -e .[baselines]`)
- Raw output: [`reports/p3_guard_baselines.json`](../reports/p3_guard_baselines.json) (Wilson 95% CIs, per-set counts, ROC-AUC, latency, memory)
- Prompt Guard 2 (Groq-hosted, accuracy only): `python -X utf8 -m scripts.baselines.run_guard_hosted` -> [`reports/p3_guard_hosted.json`](../reports/p3_guard_hosted.json)
- Same held-out sets as everywhere else in this project (see [`retraining-flow.md`](retraining-flow.md)); nothing from these sets is in any training data.

## What was and wasn't evaluated

| Model | Status | License |
|---|---|---|
| Our shipped default (rules + numpy classifier, block-on-any; the TF-IDF layer has been off since Phase 2) | evaluated | MIT (this repo) |
| `protectai/deberta-v3-base-prompt-injection-v2` (184M) | evaluated, local weights | Apache-2.0 |
| `meta-llama/Llama-Prompt-Guard-2-22M` / `-86M` | **accuracy evaluated through Groq-hosted inference** (below). **Not evaluated locally**: the weights are gated, so there is no ONNX/int8 build and no memory or CPU-latency measurement | Llama community license |
| Llama Guard 3 / 4 (1B-8B) | **not evaluated: gated**; also a content-safety classifier, so it answers a different question | Llama community license |
| "Shipped default OR ProtectAI" (block if either blocks) | evaluated | n/a |

The Meta repos on Hugging Face need the license accepted with an account and an HF token (`HF_TOKEN`), and Meta reviews access manually. No token was
available, so `run_guard_baselines.py` still records them as `not_evaluated` (re-run on 2026-09-25: "gated repo"). Groq serves both Prompt Guard 2 models on its
free tier, which made the *accuracy* comparison possible without the weights; see the hosted section below for exactly what that does and does not establish.
Llama Guard is a content-safety classifier (harm categories), not an injection detector.

**Correction to earlier revisions of this page:** the "Ours" column used the pre-Phase-2 three-layer ensemble (rules + TF-IDF + classifier). The shipped default is
now rules + classifier. Own-corpus numbers are unchanged (42/78 and 3/17); deepset is 29/60 detected with 6/56 false positives (it was 37/60 and 14/56). Everything
below uses the shipped default, and the README table was updated to match.

## Results (detection = share of attacks blocked, FPR = share of benign blocked, threshold 0.5)

| Held-out set | Shipped default | ProtectAI DeBERTa | Shipped OR ProtectAI |
|---|---|---|---|
| **Own corpus** (78 attacks / 17 benign) | 53.8% (42/78) / FPR 17.6% (3/17) | 80.8% (63/78) / FPR 23.5% (4/17) | 85.9% (67/78) / FPR 23.5% (4/17) |
| deepset test (60 / 56) | 48.3% (29/60) / FPR 10.7% (6/56) | 36.7% (22/60) / FPR 0.0% (0/56) | 56.7% (34/60) / FPR 10.7% (6/56) |
| jailbreak_llms not in training (244 attacks)* | 87.7% (214/244) | 84.4% (206/244) | 93.0% (227/244) |
| JailbreakBench benign (100), FPR | FPR 9.0% (9/100) | FPR 1.0% (1/100) | FPR 10.0% (10/100) |
| Short messages (40 benign), FPR | FPR 2.5% (1/40) | FPR 2.5% (1/40) | FPR 5.0% (2/40) |
| In-domain ops benign (30), FPR | FPR 10.0% (3/30) | FPR 10.0% (3/30) | FPR 10.0% (3/30) |

\* our TF-IDF index (no longer in the default) was fit on jailbreak_llms-derived positives; the shipped default no longer uses it, so this number is not inflated by near-duplicates the way the pre-Phase-2 figure (91.8%) may have been.

ROC-AUC (threshold-free, continuous scores only; ours = the numpy classifier layer, since the ensemble is a hard OR; PG2 from the hosted runs, first 1,500 characters):

| Set | Ours (classifier layer) | ProtectAI | PG2 22M | PG2 86M |
|---|---|---|---|---|
| Own corpus | 0.808 | 0.822 | 0.675 | 0.809 |
| deepset test | 0.873 | 0.901 | 0.834 | 0.914 |

Cost of running each. **These numbers are noisy on this machine** (a hybrid-core laptop, 14 torch threads) and are shown as measured, not as a benchmark:

| | Ours (rules + classifier) | ProtectAI DeBERTa |
|---|---|---|
| p50 latency, CPU, single example | **0.563 ms** (last run) | 72.1 ms (Phase 1), 129-148 ms (three isolated re-runs), 827 ms (a full re-run of the harness): about 128x to 1,468x ours |
| Weights on disk | **2.0 MB** | 703.5 MB |
| Incremental process RSS after load | small (numpy) | +858 MB (Phase 1), +528 MB (full re-run), +396 to +588 MB (isolated re-runs) |
| Fits Render free tier (512 MB)? | yes | **probably not once the gateway shares the instance, but this was inferred from RSS and never tested in a 512 MB container** (no Docker daemon was running here) |

### Llama Prompt Guard 2 through Groq-hosted inference

`python -X utf8 -m scripts.baselines.run_guard_hosted` (needs `GROQ_API_KEY`; free tier: 30 requests/min per model) scores both models on the same 625 held-out texts and writes
[`reports/p3_guard_hosted.json`](../reports/p3_guard_hosted.json) (per-example scores included).

- **Label mapping verified first**: on 10 hand-labelled examples the returned number read as P(malicious) is right on 10/10 for both models, and its complement on 0/10.
- **Truncation**: the hosted API rejects inputs over 512 tokens, so texts were cut to their first 1,500 characters (about 350-400 tokens). 134 of 625 texts are affected, nearly all of them
  jailbreak_llms prompts. Meta recommends scoring long inputs in segments and taking the max, which would raise those detection rates; not done here.
- **Fidelity is unverified**: this assumes Groq serves the same checkpoints as the gated repos. A parity check of hosted against local scores is still to do (needs `HF_TOKEN`).

| Held-out set | Shipped default | PG2 22M alone | PG2 86M alone | Rules + PG2 22M | Rules + classifier + PG2 22M |
|---|---|---|---|---|---|
| **Own corpus** (78 attacks / 17 benign) | 53.8% (42/78) / FPR 17.6% (3/17) | 32.1% (25/78) / FPR 11.8% (2/17) | 30.8% (24/78) / FPR 5.9% (1/17) | 48.7% (38/78) / FPR 17.6% (3/17) | 62.8% (49/78) / FPR 23.5% (4/17) |
| deepset test (60 / 56) | 48.3% (29/60) / FPR 10.7% (6/56) | 13.3% (8/60) / FPR 0.0% (0/56) | 16.7% (10/60) / FPR 0.0% (0/56) | 13.3% (8/60) / FPR 0.0% (0/56) | 48.3% (29/60) / FPR 10.7% (6/56) |
| jailbreak_llms not in training (244 attacks)* | 87.7% (214/244) | 93.4% (228/244) | 94.7% (231/244) | 93.4% (228/244) | 95.1% (232/244) |
| JailbreakBench benign (100), FPR | FPR 9.0% (9/100) | FPR 8.0% (8/100) | FPR 17.0% (17/100) | FPR 8.0% (8/100) | FPR 14.0% (14/100) |
| Short messages (40 benign), FPR | FPR 2.5% (1/40) | FPR 0.0% (0/40) | FPR 0.0% (0/40) | FPR 0.0% (0/40) | FPR 2.5% (1/40) |
| In-domain ops benign (30), FPR | FPR 10.0% (3/30) | FPR 6.7% (2/30) | FPR 3.3% (1/30) | FPR 6.7% (2/30) | FPR 10.0% (3/30) |

At a matched operating point (the guard's threshold set, on these same sets, so that pooled false positives on the 243 benign texts do not exceed the shipped default's 22; post-hoc, so optimistic for the guard):

| Detection at a matched false-positive budget | Own corpus (78) | deepset (60) | jailbreak_llms (244) |
|---|---|---|---|
| Shipped default: rules OR classifier | 53.8% (42/78) | 48.3% (29/60) | 87.7% (214/244) |
| Rules OR PG2 22M (threshold 0.068) | 57.7% (45/78) | 20.0% (12/60) | 95.9% (234/244) |
| Rules OR PG2 86M (threshold 0.098) | 57.7% (45/78) | 18.3% (11/60) | 96.7% (236/244) |

**Reading.**

1. At the default 0.5 threshold PG2 is a conservative detector: on this project's own corpus it catches 32.1% (25/78) (22M) and 30.8% (24/78) (86M), against 80.8% (63/78) for ProtectAI and 53.8% (42/78) for the shipped default;
   on deepset 13.3% (8/60) and 16.7% (10/60), against 36.7% (22/60) and 48.3% (29/60). It does better than either on jailbreak_llms (93.4% (228/244) and 94.7% (231/244)),
   the long-form jailbreak style. Its false positives are 0/56 on deepset but 8.0% (8/100) (22M) and 17.0% (17/100) (86M) on JailbreakBench benign, against 1.0% (1/100) for ProtectAI.
2. Ranking quality tells a different story for the 86M: its ROC-AUC (0.809 / 0.914) is level with ProtectAI's (0.822 / 0.901) and at or above the classifier layer's, so much of its low recall at 0.5 is the threshold. The 22M ranks clearly worse (0.675 / 0.834).
3. **The decision test (does "rules + PG2 22M" beat "rules + numpy classifier" at a similar false-positive rate?) is not met.** At the matched budget the swap is a wash on the own corpus (57.7% (45/78) vs 53.8% (42/78), +3 of 78: inside the noise), better on jailbreak_llms (+20 of 244), and
   **17 of 60 worse on deepset**, where all of the shipped default's detection comes from the classifier (the rules catch 0 of 60). The 86M gives the same picture.
4. PG2 as an extra third layer (rules + classifier + PG2 22M at 0.5) lifts the own corpus to 62.8% (49/78) and jailbreak_llms to 95.1%, but every union adds false positives: JailbreakBench benign goes from 9.0% to 14.0%. Its memory cost is unmeasured.

**Still to do, all needing the weights (`HF_TOKEN`)**: the hosted-vs-local parity check; `python -X utf8 -m scripts.baselines.onnx_quantize_guard --model pg2-22m` (and `pg2-86m`), which is parameterized but has **not been run** on Prompt Guard;
local RSS and latency; and `docker run -m 512m` for the candidate ensembles. Given point 3 the 22M ensemble is not a priority. The 86M as an additional third layer is the only variant with a possible case (own corpus 49/78 vs 42/78 at the same 3/17 own-corpus false positives), but it takes JailbreakBench false positives from 9% to 21%, so even that has a cost; the memory of an int8 build decides whether it is worth trying.

## Reading the numbers

1. **On the corpus this gateway was built for, ProtectAI is clearly the better detector.** At the default threshold it catches 80.8% vs the shipped default's 53.8%, at a similar
   false-positive count (4 vs 3 of 17). Not just an operating-point artifact: lowering the classifier's threshold to 0.35 so the shipped default also blocks 4 of 17 benign
   gives 57.7% (45/78) detection (post-hoc, chosen on the evaluation set, so optimistic for us). ROC-AUC is level (0.808 vs 0.822); with only 17 benign cases the AUC is very noisy.
2. **On deepset ProtectAI is far more precise** (0 of 56 benign blocked vs 6) but catches fewer attacks (36.7% vs 48.3%). The shipped default is much less trigger-happy than it was
   before Phase 2 (6/56 false positives, was 14/56), at the cost of 8 detections.
3. **On the pure-benign sets** the guard model is equal or better everywhere, 9x better on JailbreakBench benign (1% vs 9%).
4. **"Shipped OR ProtectAI" maximises recall** (85.9% own corpus, 93.0% jailbreak_llms) **and inherits the union of false positives**; on deepset it adds 5 detections (34/60) and no false positives.
5. **Prompt Guard 2** (hosted evaluation above) is not a better detector than either on this project's own corpus or deepset; it is better on long jailbreaks.
6. **Small samples.** 17 benign and 78 attack cases on our own corpus; intervals are wide (see the JSON). Single-digit differences are noise; the 27-point own-corpus gap between ProtectAI and the shipped default is not.

## Decision: what ships, and why

**Serving is unchanged: the from-scratch ensemble (rules + numpy classifier) ships.** Not because it is the better detector (on the own corpus ProtectAI is) but because it is the only one
that fits the constraint this project is built around: a free 512 MB instance, torch-free. Llama Prompt Guard 2 was evaluated (hosted) as a possible replacement for the classifier and
**was not adopted**: at a matched false-positive budget it does not beat the classifier on the own corpus or deepset, and it needs gated weights, a new runtime dependency and an unmeasured
memory cost. ProtectAI stays out because it does not fit the memory budget (see the cost table for the range of measurements and the caveat that no container test was run).

Options for anyone who wants a stronger detector than the shipped default:

- run a guard model as a separate service (or on a larger instance / GPU) and call it from the gateway, accepting the latency and cost;
- call a hosted guard (Groq serves Prompt Guard 2 free at 30 requests/min) as an optional extra layer: no memory cost here, but prompts leave the box, it adds network latency, it is quota-limited,
  and on this data it adds detection mainly on long jailbreaks while adding false positives; not built;
- keep the numpy ensemble as a fast first pass and route only uncertain or high-value requests to the guard model;
- distill the guard model into the small classifier (the repo already has `scripts/distill_to_student.py`).

**What this means for the project's claims:** the from-scratch classifier is a defensible engineering exercise (tiny, fast, parity-tested, torch-free), not a detector a team should prefer over an
existing guard model when memory and latency are available. The README says so.
