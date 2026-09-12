# Real sentence-transformer embeddings for layer 2: measured, not assumed

`gateway/detectors/embedding_similarity.py` has used TF-IDF + cosine similarity
since 2026-09-05 as a documented stand-in for the build doc's actual layer-2
design — transformer sentence embeddings — because the original build
environment couldn't reach huggingface.co. That constraint doesn't apply here
(confirmed reachable, see `docs/decisions.md`'s 2026-09-11 DistilBERT entries).
So the natural next question — "would a real embedding actually fix this dead
layer?" — was tested, not assumed, via
[`scripts/evaluate_sentence_transformer_similarity.py`](../scripts/evaluate_sentence_transformer_similarity.py).

## Setup

- `sentence-transformers/all-MiniLM-L6-v2` (384-dim, normalized embeddings,
  cosine similarity via dot product).
- **Same known-bad index as TF-IDF**: `data/train.csv`, `label==1` (1,000
  rows) — same content, different embedding, so this is a fair swap-in
  comparison, not a different experiment.
- **Threshold swept, not reused from TF-IDF.** TF-IDF's 0.35 is a
  cosine-similarity score in TF-IDF's vector space; MiniLM's cosine
  similarities live in a different distribution entirely, so reusing 0.35
  would be a silent methodology bug. Swept 0.30–0.70 in steps of 0.05,
  selected the threshold with the highest detection rate among those at 0%
  false positives — the same selection principle TF-IDF's own 0.35 was chosen
  under (see `docs/decisions.md`).

## Result

| Threshold | Detection rate | False-positive rate |
|---|---|---|
| 0.30 | 80% (24/30) | 75% (3/4) |
| 0.35 | 63% (19/30) | 50% (2/4) |
| 0.40 | 43% (13/30) | 50% (2/4) |
| **0.45** | **23% (7/30)** | **0% (0/4)** |
| 0.50 | 17% (5/30) | 0% (0/4) |
| 0.55 | 3% (1/30) | 0% (0/4) |
| 0.60 | 3% (1/30) | 0% (0/4) |
| 0.65–0.70 | 0% (0/30) | 0% (0/4) |

**Best (0.45): 23% detection at 0% false positives, avg latency 44.2ms.**

| Layer | Detection rate | False-positive rate | Avg latency (ms) |
|---|---|---|---|
| embedding_similarity (TF-IDF, production default) | 0% (0/30) | 0% (0/4) | 7.1 |
| **embedding_similarity_st (sentence-transformer, opt-in)** | **23% (7/30)** | **0% (0/4)** | **44.2** |
| scratch_classifier (production) | 50% (15/30) | 0% (0/4) | 0.1 |

## The honest read

**TF-IDF really is dead weight — this confirms it wasn't a threshold-tuning
problem, it's an architecture problem.** A real semantic embedding, on the
exact same known-bad index, goes from 0% to 23% detection at the same 0% false
positive discipline. That's a genuine, non-leaked improvement (contrast with
the LOO-CV result in `docs/embedding_loo_result.md`, which needed to leak
sibling corpus cases into the index to reach 17% — this 23% comes from the
public dataset alone, the same one TF-IDF gets 0% from).

**It's still the weakest real detector, at the highest cost.** 23% is well
below `scratch_classifier`'s 50%, at ~440x its latency (44.2ms vs 0.1ms) and
~6x TF-IDF's (44.2ms vs 7.1ms). At looser thresholds detection climbs
fast (80% at 0.30) but false positives climb faster (75% at 0.30) — the
precision/recall curve doesn't offer a threshold that's both high-detection
and low-FP the way a better-trained detector would.

**Decision: opt-in (`EMBEDDING_BACKEND=sentence_transformer`), not the
default.** Reasoning, explicit rather than assumed:
1. It would re-introduce torch into the serving path specifically for this
   layer — the exact dependency `gateway/detectors/classifier_numpy.py` was
   built to remove so the full ensemble fits Render's 512MB free tier
   (`docs/decisions.md`, 2026-09-11). Trading that win away for a 23%-at-best
   layer isn't a good trade.
2. `scratch_classifier` already outperforms it on every axis measured, at a
   small fraction of the cost, in production today.
3. Real, measured, and adopted-as-optional is a more honest outcome than
   either leaving TF-IDF's "0% detecting" claim to speak for itself, or
   silently swapping in something heavier without measuring whether it
   actually helps enough to be worth it — the same discipline
   `docs/embedding_loo_result.md` already applied to a different variant of
   this exact question.

## Reproducing this

```bash
pip install sentence-transformers   # or: pip install ".[semantic]"
python scripts/fit_sentence_transformer_detector.py         # builds models/embedding_similarity_st/
python scripts/evaluate_sentence_transformer_similarity.py  # the sweep above
EMBEDDING_BACKEND=sentence_transformer uvicorn gateway.app:app --port 8000
```

Raw sweep data: [`sentence_transformer_similarity_raw_result.json`](sentence_transformer_similarity_raw_result.json).
