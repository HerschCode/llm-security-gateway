# Train/Test Leakage: Found, Fixed, and the Real Numbers

## What happened

While expanding the corpus from 20 to 36 cases and sanity-checking the new Unicode-
obfuscation cases (GW-021/022/023), three of them came back from the embedding-
similarity detector with a similarity score of **exactly 1.000** — not "very similar,"
identical. That's not a plausible outcome for genuine semantic/lexical similarity to a
*different* text; it means the detector found the exact same string already sitting in
its known-bad reference index.

It had. `scripts/prepare_training_data.py`'s original `load_our_corpus()` returned our
corpus's payloads twice: once (unchanged, verbatim) as `eval.csv` rows, and again
(mostly unchanged — only multi-turn cases were altered, via the trigger-segment
extraction from the earlier false-positive fix) as `train.csv` rows, which then get
indexed by `scripts/fit_embedding_detector.py` and trained on by
`scripts/train_scratch_classifier.py`.

Checked how widespread it was:

```
LEAKED (exact payload also in train.csv): 30/36
['GW-001', 'GW-002', 'GW-003', 'GW-004', 'GW-005', 'GW-006', 'GW-010', 'GW-011',
 'GW-012', 'GW-013', 'GW-014', 'GW-015', 'GW-016', 'GW-017', 'GW-018', 'GW-019',
 'GW-020', 'GW-021', 'GW-022', 'GW-023', 'GW-024', 'GW-025', 'GW-026', 'GW-029',
 'GW-030', 'GW-031', 'GW-032', 'GW-033', 'GW-034', 'GW-036']

Clean (not verbatim in train.csv): 6/36
['GW-007', 'GW-008', 'GW-009', 'GW-027', 'GW-028', 'GW-035']
```

Every single-message case leaked. Only the six multi-turn cases were clean, and only
because of the *previous* fix (extracting just the trigger turn for training) — which
happened to also break the exact-string match, not because leakage was being actively
guarded against. This had been present since the very first evaluation run in this
project (the v0.1.0 20-case numbers reported earlier were already partly inflated by
it), and got worse as the corpus grew, since every new case added another exact-match
"gimme" for the embedding index in particular.

## The fix

`load_our_corpus()` no longer returns anything for training. The corpus is now
**strictly held-out eval data** — it contributes zero rows to `data/train.csv`. Training
comes only from the public `verazuo/jailbreak_llms` dataset and the in-domain benign
queries (`corpus/benign_indomain_queries.yaml`, itself unaffected by this bug since it
was already train/eval-split correctly from the start). Verified zero leakage
programmatically before re-running anything:

```
Leaked cases now: (none -- clean)
```

## The real numbers (before vs. after)

| Layer | Detection rate (leaked) | Detection rate (honest) |
|---|---|---|
| rule_based | 23% (7/30) | 23% (7/30) — unaffected, not ML-based |
| embedding_similarity | **97% (29/30)** | **0% (0/30)** |
| scratch_classifier | 87% (26/30) | 63% (19/30) |

**Embedding-similarity's headline number was almost entirely leakage.** With the leak
fixed, it detects *zero* of our 36 corpus attacks. This is the single most important
finding in this project. It means: TF-IDF similarity against a general public
jailbreak/Reddit-prompt dataset provides no measurable generalization to a differently-
styled, hand-written attack corpus. The earlier 94-97% numbers reported in this
project's history were not a real result — they were the detector recognizing its own
answer key.

The classifier's drop (87% -> 63%) is smaller but real for the same reason: some of its
apparent skill was memorizing exact corpus text rather than learning the underlying
injection pattern.

## Why this matters more than any other finding in this project

A narrow eval corpus hiding a false-positive problem (see `docs/domain_shift_fix.md`)
is a data-coverage problem. This is worse: it's a **methodology** problem, where the
*same* text served as both the answer key and the exam question. Any of the earlier
"before/after" stories in this project that cited embedding-similarity's 94-97%
detection rate should be read with that number replaced by 0% going forward — the
comparison table, README, and CLI report have all been regenerated to reflect this.

## What this means for the project's actual conclusion

Rule-based (23%) and embedding-similarity (0%, honestly measured) are both
essentially non-functional against this corpus on their own. The from-scratch
classifier (63% detection, 25% false-positive rate) is the only layer doing real,
non-leaked work, and it's mediocre, not excellent. The gateway's live end-to-end
protection numbers reported earlier (19/20 -- now needs rechecking against the
36-case corpus, see updated `docs/redteam_report_gateway.md`) reflect the ensemble
of all three layers together, including rule-based catching the most literal
attacks outright, not any single layer being strong in isolation.

## Lesson

Any time a detector's score against its own eval set looks *too* good, check for
leakage before reporting the number. A perfect or near-perfect similarity score,
specifically, is a leakage smell, not a success signal — genuine semantic similarity
between two different pieces of text is essentially never exactly 1.000.
