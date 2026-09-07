# Embedding-Similarity: Leave-One-Out Cross-Validation Result

Tests whether indexing our OWN corpus (not just the public dataset) into the
embedding-similarity known-bad set helps, WITHOUT leaking -- each case is
tested against an index built from every OTHER case, never itself. See this
script's module docstring and `docs/leakage_fix.md` for why this methodology
matters.

**LOO detection rate: 17% (5/30)**
**LOO false-positive rate: 25% (1/4)**

Compare to the comparison table's honest public-dataset-only number: **0%**.

## Missed even with LOO (novel enough that no other corpus example resembles them)

- GW-002
- GW-003
- GW-004
- GW-005
- GW-006
- GW-007
- GW-008
- GW-009
- GW-010
- GW-011
- GW-012
- GW-013
- GW-016
- GW-017
- GW-021
- GW-022
- GW-023
- GW-024
- GW-026
- GW-028
- GW-029
- GW-030
- GW-031
- GW-032
- GW-033

## False positives under LOO

- GW-035

## What this means

If LOO detection rate is meaningfully above 0%, it means embedding-similarity's usefulness in this project depends entirely on it having seen attacks *like* the one it's catching -- it's a lookup against known patterns, not a general injection detector. That's a legitimate design (real threat-intel-based detection works this way too), but it means every genuinely novel attack family will be missed until a human adds an example of it to the corpus. Worth deciding explicitly whether that's an acceptable production trade-off, not something to discover after deployment.
