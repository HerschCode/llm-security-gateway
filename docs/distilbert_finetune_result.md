# DistilBERT fine-tune: the real result

`scripts/train_distilbert_finetune.py` sat "written, never run" for most of
this project's life because the original build sandbox couldn't reach
huggingface.co. From this environment it can. Ran it for real on 2026-09-11 —
this is the actual result, not the prediction the script's docstring used to
carry in its place.

## Setup

- `distilbert-base-uncased`, 3 epochs, batch size 32, lr 2e-5 — same
  hyperparameters the script always specified.
- **Same train/eval split as the scratch classifier**: `data/train.csv` (2,020
  rows), `data/eval.csv` (the 36-case corpus, held out from training).
- **Same scoring methodology as `scripts/evaluate.py`**: detection rate =
  recall on `expected_behavior == "block"`, false-positive rate = block rate
  on `expected_behavior == "allow"`, GW-018/GW-036 (`flag`) reported
  separately, per-case latency measured as a single (unbatched) forward pass —
  an apples-to-apples 4th row for `docs/comparison_table.md`, not a different
  metric that happens to look comparable.

## Result

| Layer | Detection rate | False-positive rate | Avg latency (ms) |
|---|---|---|---|
| scratch_classifier | 50% (15/30) | 0% (0/4) | 0.107 |
| **distilbert_finetuned** | **50% (15/30)** | **0% (0/4)** | **34.855** |

**Identical detection rate and false-positive rate on the standard corpus.**
Not close — exactly the same fractions.

## The domain-shift test — the part that actually mattered

The standard corpus only has 4 "should allow" cases, too few to say anything
about generalization. `docs/domain_shift_fix.md` already found that the
scratch classifier's real weakness is a residual **10% false-positive rate**
(1/10) on realistic in-domain benign queries it never trained on — that's the
number the "pretrained language understanding should generalize better"
hypothesis was actually about. Ran the fine-tuned DistilBERT against the exact
same held-out benign set (`scripts/measure_distilbert_domain_shift.py`):

**DistilBERT: 1/10 (10%) — the same false positive, on the same query**
(`"What's our current SLA breach rate this quarter?"`), **at the same rate.**

## The honest conclusion

The prediction this script's docstring carried for months —
"a real DistilBERT fine-tune should meaningfully outperform the from-scratch
classifier" — **did not hold.** On every metric measured, including the one
metric domain_shift_fix.md identified as the real test, pretrained language
understanding bought nothing over a randomly-initialized embedding matrix
trained on the same ~2,000 rows. It did cost something concrete: **~325x the
latency** (34.9ms vs 0.11ms per request) for identical accuracy.

Plausible reasons, stated as reasoning rather than as a second unverified
claim:
- 2,020 training rows may simply not be enough data for either architecture to
  do meaningfully better than the other — the bottleneck could be data volume,
  not model capacity or pretraining.
- The corpus's attacks were deliberately written to be lexically diverse from
  each other (see `docs/embedding_loo_result.md`'s finding that even
  leave-one-out lexical similarity struggles here) — a property that may
  resist both a mean-pooled embedding *and* a transformer's attention if the
  underlying signal isn't there in 2,000 examples either way.
- 3 epochs / this exact learning rate may not be the right recipe for
  DistilBERT on a dataset this size — untuned, not exhaustively searched.

**What this changes:** nothing about which model is in production —
`gateway/detectors/classifier_numpy.py` (the from-scratch classifier, served
torch-free — see `docs/decisions.md`, 2026-09-11) remains the right choice: same
accuracy, ~325x lower latency, zero deep-learning framework in the serving
path. This result closes the "never run, hypothesis untested" gap honestly:
the hypothesis was tested and didn't hold, which is a more useful thing to
know than "presumably better, someday, if run."

## Reproducing this

```bash
pip install -r requirements.txt
pip install transformers datasets accelerate   # or: pip install ".[finetune]"
python scripts/train_distilbert_finetune.py            # ~50-65 min on a modern CPU, no GPU required
python scripts/measure_distilbert_domain_shift.py       # needs the model this just trained
```

One training run in this environment took ~63 minutes total, including one
unexplained ~33-minute stall between steps 112–113 (mid-epoch-2 checkpoint
save) that wasn't diagnosed — noted rather than silently averaged away, since
this project doesn't paper over things it didn't actually investigate.

Raw numbers: [`distilbert_finetune_raw_result.json`](distilbert_finetune_raw_result.json).
