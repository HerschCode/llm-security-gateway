# Phase 2: retire or repair the dead layer

**Question.** The TF-IDF similarity layer detects 0% of this project's own attack corpus. Should it
stay in the default ensemble, be replaced by something better, or go?

- Ablation: `python -X utf8 -m scripts.baselines.ensemble_ablation` -> [`reports/p3_ensemble_ablation.json`](../reports/p3_ensemble_ablation.json)
- ONNX / int8: `python -X utf8 -m scripts.baselines.onnx_quantize_guard` -> [`reports/p3_onnx_quantization.json`](../reports/p3_onnx_quantization.json)
- Same held-out sets and caveats as [`guard-baselines.md`](guard-baselines.md): 17 benign own-corpus cases;
  TF-IDF and sentence-transformer indexes are fit on jailbreak_llms-derived positives, so jailbreak-style
  sets flatter them. Block-on-any compositions; detection / FPR with Wilson CIs in the JSON.

## 1. Ablation (detection / false-positive rate)

| Composition | own corpus | deepset test | JailbreakBench benign | short msgs | in-domain ops | jailbreak_llms clean |
|---|---|---|---|---|---|---|
| rule + TF-IDF + clf (**before**) | 54% / 18% | 62% / 25% | - / 10% | - / 2.5% | - / 10% | 92% / - |
| **rule + clf (after: TF-IDF removed)** | **54% / 18%** | 48% / **11%** | - / 9% | - / 2.5% | - / 10% | 88% / - |
| rule + sentence-transformer + clf | 59% / 18% | 50% / 11% | - / **24%** | - / 2.5% | - / 10% | 96% / - |
| rule + guard (reference, not deployable) | 83% / 24% | 37% / 0% | - / 1% | - / 2.5% | - / 10% | 85% / - |
| rule + clf + guard (reference) | 86% / 24% | 57% / 11% | - / 10% | - / 5% | - / 10% | 93% / - |

Exact counts, before to after: own corpus 42/78 detected and 3/17 false positives (identical);
deepset 37/60 to 29/60 detected and 14/56 to 6/56 false positives; JailbreakBench benign 10/100 to 9/100;
jailbreak_llms clean 224/244 to 214/244. p50 latency of the ensemble on this CPU: **4.4 ms to 0.11 ms**.

Reading it:
- On the corpus the gateway is built for, TF-IDF contributes nothing (0/78 alone).
- On deepset it is roughly a coin flip: removing it costs 8 attacks caught and saves 8 false positives, and
  the remaining operating point is more precise (29 of 35 blocked prompts are real attacks, vs 37 of 51).
- On jailbreak_llms it contributes 10 more detections, but that set overlaps the TF-IDF index's training
  source, so this is the least trustworthy number here.
- It is also the single most expensive layer (about 4 ms of a 4.4 ms ensemble).

## 2. Repair attempt A: swap in the sentence-transformer (fp32)

Better on own corpus (+5 points) and jailbreak_llms, but **JailbreakBench benign false positives jump
from 9% to 24%** and latency doubles (9.1 ms p50) and it needs torch. Not a repair. (An int8 ONNX MiniLM
would shrink the footprint, but the false positives come from the similarity scores themselves, so it was
not pursued; that reasoning is untested.)

## 3. Repair attempt B: make the guard model servable (ONNX Runtime + int8)

ProtectAI DeBERTa exported to ONNX and measured against the fp32 PyTorch model. RSS is the incremental
resident memory of a fresh process; the free tier has 512 MB total.

| Variant | Size | RSS | p50 latency | Own-corpus detection / FPR | deepset detection / FPR | AUC own / deepset | Decision agreement (own corpus) |
|---|---|---|---|---|---|---|---|
| PyTorch fp32 (reference) | 704 MB | +858 MB | 82 ms | 81% / 24% | 37% / 0% | 0.82 / 0.90 | - |
| ONNX fp32 | 704 MB | +771 MB | 33 ms | 81% / 24% | 37% / 0% | 0.82 / 0.90 | 100% |
| int8 MatMul (dynamic) | 514 MB | +533 MB | 20 ms | **12%** / 0% | 7% / 0% | 0.80 / 0.72 | **35%** |
| int8 MatMul + embeddings | 233 MB | +252 MB | **110 ms** | **10%** / 0% | 7% / 0% | 0.79 / 0.71 | **34%** |
| int8 per-channel | 514 MB | +534 MB | 19 ms | 64% / 18% | 15% / 0% | 0.76 / 0.77 | 79% |
| int8 feed-forward only, per-channel | 541 MB | +612 MB | 25 ms | 62% / 24% | 15% / 0% | 0.78 / 0.79 | 80% |

Latency varies run to run (PyTorch fp32 measured 72 ms in `guard-baselines.md` and 82 ms here); the ratios matter, not the last digit.

Negative results, stated plainly:
1. **Naive dynamic int8 quantization breaks this model**: own-corpus detection collapses from 81% to
   10-12%. DeBERTa's disentangled attention is quantization-sensitive; per-channel weights and leaving
   attention in fp32 recover part of it (62-64%) but not all, and AUC stays clearly below fp32 (deepset
   0.77-0.79 vs 0.90).
2. **The only variant small enough for the free tier is broken and slow** (233 MB, 10% detection, 110 ms),
   because the 128k-token embedding table dominates the model's size.
3. **ONNX fp32 is exact and 2.5x faster than PyTorch, but still 771 MB**: over the 512 MB limit by itself.
4. Untried, and the realistic next steps: quantization-aware fine-tuning, static quantization with
   calibration data, pruning the embedding vocabulary to the tokens actually used, or a smaller guard
   model (Prompt Guard 2 22M, if access is granted).

## Decision

**TF-IDF removed from the default ensemble** (`EMBEDDING_BACKEND` default is now `none`; `tfidf` and
`sentence_transformer` remain opt-in; unknown values raise instead of silently falling back). Own-corpus
results are unchanged, deepset false positives fall from 25% to 11%, and the ensemble is about 40x
faster. The layer is kept as a documented ablation, and its scripts and index are unchanged.

**The guard model is not added to serving.** No variant both fits the 512 MB tier and keeps its
accuracy. The shipped ensemble is now rule-based + the numpy classifier, and the README says the
existing guard model is the better detector where memory allows.
