# Guard-model baselines (Phase 1)

**Question:** why build a detector from scratch when purpose-built guard models exist?
This measures it. One script, one table, raw JSON, negative results kept.

- Script: `python -X utf8 -m scripts.baselines.run_guard_baselines` (optional extra: `pip install -e .[baselines]`)
- Raw output: [`reports/p3_guard_baselines.json`](../reports/p3_guard_baselines.json) (Wilson 95% CIs, per-set counts, ROC-AUC, latency, memory)
- Same held-out sets as everywhere else in this project (see [`retraining-flow.md`](retraining-flow.md)); nothing from these sets is in any training data.

## What was and wasn't evaluated

| Model | Status | License |
|---|---|---|
| Our shipped ensemble (rules + TF-IDF + numpy classifier, block-on-any) | evaluated | MIT (this repo) |
| `protectai/deberta-v3-base-prompt-injection-v2` (184M) | evaluated | Apache-2.0 |
| `meta-llama/Llama-Prompt-Guard-2-86M` / `-22M` | **not evaluated: gated** | Llama community license |
| Llama Guard 3 / 4 (1B-8B) | **not evaluated: gated** | Llama community license |
| "Our ensemble OR ProtectAI" (block if either blocks) | evaluated | n/a |

The Meta repos require accepting Meta's license on huggingface.co with an account and an HF token
(`HF_TOKEN`); Meta reviews access manually, and none was available in this environment, so the script
records them as `not_evaluated` rather than dropping them. The script is written to load them once
`HF_TOKEN` is set, but that path is **untested** (no access to try it), including the label mapping
for their output classes. Llama Guard is also a *content-safety* classifier (harm categories), not an
injection detector, so it answers a different question than the others even when it can be run.

## Results (detection = share of attacks blocked, FPR = share of benign blocked, threshold 0.5)

| Held-out set | Ours | ProtectAI DeBERTa | Ours OR ProtectAI |
|---|---|---|---|
| **Own corpus** (78 attacks / 17 benign) | 53.8% (42/78) / FPR 17.6% (3/17) | **80.8%** (63/78) / FPR 23.5% (4/17) | **85.9%** (67/78) / FPR 23.5% (4/17) |
| deepset test (60 / 56) | 61.7% (37/60) / FPR 25.0% (14/56) | 36.7% (22/60) / FPR **0.0%** (0/56) | 68.3% (41/60) / FPR 25.0% (14/56) |
| jailbreak_llms not in training (244 attacks)* | 91.8% (224/244) | 84.4% (206/244) | 94.7% (231/244) |
| JailbreakBench benign (100), FPR | 10.0% (10/100) | **1.0%** (1/100) | 11.0% (11/100) |
| Short messages (40 benign), FPR | 2.5% (1/40) | 2.5% (1/40) | 5.0% (2/40) |
| In-domain ops benign (30), FPR | 10.0% (3/30) | 10.0% (3/30) | 10.0% (3/30) |

\* our TF-IDF index is fit on jailbreak_llms-derived positives, so our number here likely benefits from near-duplicates.

ROC-AUC (threshold-free, continuous scores only; ours = the numpy classifier layer, since the ensemble is a hard OR):

| Set | Ours (classifier layer) | ProtectAI |
|---|---|---|
| Own corpus | 0.808 | 0.822 |
| deepset test | 0.873 | 0.901 |

Cost of running each:

| | Ours (3 layers) | ProtectAI DeBERTa |
|---|---|---|
| p50 latency, CPU, single example | **4.1 ms** | 72.1 ms (17.5x slower) |
| Weights on disk | **2.0 MB** | 703.5 MB |
| Incremental process RSS after load | small (numpy) | **+858 MB** |
| Fits Render free tier (512 MB)? | yes | **no, by itself** |

## Reading the numbers

1. **On the corpus this gateway was built for, the guard model is clearly the better detector.**
   At the default threshold it catches 80.8% vs our 53.8%, at a similar false-positive count. This is
   not just an operating-point artifact: lowering our classifier's threshold until its false-positive
   count matches the guard's (4 of 17) still gives only 53.8% detection (post-hoc, chosen on the
   evaluation set itself, so optimistic for us). ROC-AUC is nearly equal (0.81 vs 0.82), which says
   the two rank similarly overall; with only 17 benign cases the AUC is very noisy and the curves differ
   mainly in the low-false-positive region.
2. **On deepset the guard model is far more precise** (0 of 56 benign blocked vs our 14) but catches
   fewer attacks (36.7% vs 61.7%). It is conservative there; our ensemble is trigger-happy.
3. **On the pure-benign sets** the guard model is equal or better everywhere, 10x better on
   JailbreakBench benign (1% vs 10%).
4. **"Ours OR guard" maximises recall (85.9% on own corpus, 94.7% on jailbreak_llms) but inherits the
   union of both models' false positives**, so it does not fix precision: deepset FPR stays 25% because
   an OR can only add blocks. A precision-oriented combination (for example, guard as the only learned
   layer plus rules) was not tested here; it belongs to Phase 2.
5. **Small samples.** 17 benign and 78 attack cases on our own corpus; intervals are wide (see JSON).
   Single-digit differences are noise; the 27-point own-corpus detection gap is not.

## Decision: what ships, and why

**Serving is unchanged: the from-scratch ensemble ships.** Not because it is the better detector
(on own corpus it is not) but because it is the only one that fits the constraint this project is
built around: a free 512 MB instance. The guard model needs about 860 MB of resident memory on its own
and is 17.5x slower at p50 on CPU, so it cannot be a layer in the free-tier deploy. Options for anyone
who wants the better detector:

- run the guard model as a separate service (or on a larger instance / GPU) and call it from the
  gateway, accepting the latency and cost;
- keep the numpy ensemble as a fast first pass and route only uncertain or high-value requests to the
  guard model;
- distill the guard model into the small classifier (the repo already has `scripts/distill_to_student.py`).

**What this means for the project's claims:** the from-scratch classifier is a defensible engineering
exercise (tiny, fast, parity-tested, torch-free), not a detector a team should prefer over an existing
guard model when memory and latency are available. The README says so.
