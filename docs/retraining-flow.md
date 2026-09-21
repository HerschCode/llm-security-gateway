# Retraining the classifier: what we tried, what helped, what didn't

Continues [`recalibration-flow.md`](recalibration-flow.md). That step showed that moving
thresholds cannot help because the classifier's raw score barely separates attacks from benign
prompts on independent data (ROC-AUC 0.61 on held-out deepset). So this step improves the score
itself, by training on more diverse data. Scripts: `scripts/retrain_classifier_v2.py`
(ablation), `scripts/evaluate_shipped_heldout.py` (shipped serving path). Raw results:
`reports/p3_retrain_v2.json`, `reports/p3_shipped_heldout.json`.

![Retraining results](retraining-results.png)

## Method
Same tiny architecture (mean-pooled embeddings + MLP), hyperparameters and seeds throughout;
only the training data changes. Every held-out text is removed from all training sets by exact
match (near-duplicates are not detected). 3 seeds per configuration.

| Config | Adds | Train rows (attack / benign) |
|---|---|---|
| v1 | `data/train.csv` only (jailbreak_llms + regular prompts + in-domain benign), retrained here | 1,836 |
| A | + deepset/prompt-injections train split | 2,382 |
| B | + Lakera/gandalf, jackhhao/jailbreak-classification, xTRam1/safe-guard (train splits / sample) | 6,372 |
| C | + generic benign instructions (alpaca-cleaned 1,500; dolly-15k 1,000) | 8,856 |
| D (shipped) | + hand-written short chat messages (86 written, 83 added after de-duplication) | 8,939 (3,015 / 5,924) |

Held-out: deepset test, JailbreakBench benign, jailbreak_llms not in training, safe-guard /
jackhhao / gandalf test splits, 40 hand-written short messages, and our own corpus.

## Ablation (mean over 3 seeds, classifier alone at threshold 0.5, no length guard)
| Config | deepset test AUC | JailbreakBench benign FPR | short-message FPR | own-corpus AUC |
|---|---|---|---|---|
| v1 | 0.56 | 29% | 43% | 0.55 |
| A | 0.88 | 25% | 36% | 0.73 |
| B | 0.83 | 20% | 21% | 0.71 |
| C | 0.82 | 9% | 23% | 0.79 |
| D | 0.81 | 6% | 26% | 0.79 |

## The result that should be trusted: leave-one-source-out
Test splits of sources that were in training (safe-guard, jackhhao, gandalf in B/C/D) are
same-distribution and overstate generalisation: the classifier scores 0.99 AUC on safe-guard
test once safe-guard train is in training. The honest test of a new distribution is to remove
one source and test on it (config C without that source):

| Held-out source (excluded from training) | v1 AUC | Retrained AUC | Detection / FPR at 0.5, v1 | Detection / FPR at 0.5, retrained |
|---|---|---|---|---|
| deepset | 0.556 | 0.710 | 53% / 41% | 24% / 13% |
| safe-guard | 0.547 | 0.896 | 47% / 35% | 59% / 4% |
| jackhhao | 0.914 | 0.942 | 91% / 29% | 86% / 14% |
| gandalf (attacks only) | n/a | n/a | 35% detection | 85% detection |

Retraining generalises to a new source, but unevenly: large gains on safe-guard and gandalf,
moderate on deepset (AUC 0.56 to 0.71, still weak), and a detection cost on deepset at the
fixed 0.5 threshold.

## A failure found along the way
After the first swap, an existing test failed: the classifier blocked "hello" (0.81), "thanks"
(0.60) and "ok" (0.995). The old v1 model did the same ("ok" 1.0, "test" 0.81): mean-pooling
makes a 1-2 word input depend on a single token embedding. Adding short benign messages did
not fix it (held-out short-message FPR stayed 21-26% across B, C and D), so the fix is a policy
guard: the classifier skips inputs shorter than 3 word tokens (the rule-based layer still runs).
Across the ~1,280 held-out attacks, only 2 are that short. The guard is applied to v1 and shipped
alike in the comparison below, and it is covered by a unit test.

## Shipped ensemble vs v1 (same layers, same guard; block if any layer blocks)
| Held-out set | v1 ensemble | Shipped ensemble | Note |
|---|---|---|---|
| JailbreakBench benign, FPR (n=100) | 26% | **7%** | never trained on |
| Short messages, FPR (n=40) | 22.5% | **5%** | measured after the guard for both |
| deepset test benign, FPR (n=56) | 55% | **23%** | same-source split (deepset train is in training) |
| jailbreak_llms not in training, detection (n=244) | 94.3% | 90.6% | small cost |
| deepset test, detection (n=60) | 78% | 60% | same-source split |
| Own corpus, detection (n=78) | 61.5% | 61.5% | unchanged |
| **Own corpus, benign FPR (n=17)** | 23.5% | **29.4%** | **worse by 1 of 17; CI wide** |

## What did not get fixed
- **False positives on our own in-domain benign queries did not improve** (4 to 5 of 17
  blocked; the interval is 13-53%). The added data is generic; in-domain operational language
  (order numbers, suppliers, SLAs) is not represented in the external sets.
- **deepset is still the hardest set** (AUC 0.71 when left out of training). Its German text and
  short natural-language injections look unlike the training sources.
- **Detection dropped where the ensemble leaned on the old classifier**: jailbreak-style prompts
  (94% to 91%), and on our own corpus the classifier's per-category detection moved unevenly
  (direct injection 62% to 85%, multi-turn jailbreak 47% to 33%, tool-scope escalation 40% to
  33%; regenerated `docs/comparison_table.md`).
- **The embedding layer was not changed.** Its TF-IDF index is fit on v1 positives, so its
  jailbreak-style numbers are inflated by near-duplicates, and it is responsible for most of
  the remaining false positives on deepset benign (9 of 13).
- **Score instability on paraphrases.** Near-identical soft-exception phrasings scored anywhere from 0.002 to 0.935 while restoring a near-threshold test (see `tests/test_middleware.py`). The classifier is a small bag-of-embeddings model; borderline inputs land on either side of the threshold by small wording changes.
- Three seeds and small held-out sets: treat single-digit differences as noise. The shipped model
  is seed 0 of config D.

## Reproducing
Download the datasets listed in `docs/corpus-references.md` into `data/external/` (gitignored),
then `python -X utf8 -m scripts.retrain_classifier_v2 --seeds 3 --save-best D`, copy the saved
model into `models/scratch_classifier/`, and run `python scripts/export_classifier_to_numpy.py`.
The previous weights are kept in `models/scratch_classifier_v1/`.
`scripts/train_scratch_classifier.py` reproduces v1 only.
