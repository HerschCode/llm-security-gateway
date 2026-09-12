# Embedding-Similarity: Leave-One-Out Cross-Validation Result

Tests whether indexing our OWN corpus (not just the public dataset) into the
embedding-similarity known-bad set helps, WITHOUT leaking -- each case is
tested against an index built from every OTHER case, never itself. See this
script's module docstring and `docs/leakage_fix.md` for why this methodology
matters.

**LOO detection rate: 32% (18/56)**
**LOO false-positive rate: 33% (4/12)**

Compare to the comparison table's honest public-dataset-only number: **0%**.

## Missed even with LOO (novel enough that no other corpus example resembles them)

- GW-003
- GW-006
- GW-007
- GW-008
- GW-009
- GW-011
- GW-012
- GW-013
- GW-016
- GW-021
- GW-022
- GW-023
- GW-024
- GW-026
- GW-028
- GW-029
- GW-031
- GW-032
- GW-033
- GW-037
- GW-038
- GW-039
- GW-041
- GW-042
- GW-045
- GW-047
- GW-050
- GW-051
- GW-053
- GW-054
- GW-055
- GW-058
- GW-059
- GW-061
- GW-062
- GW-065
- GW-068
- GW-069

## False positives under LOO

- GW-020
- GW-048
- GW-056
- GW-072

## What this means

If LOO detection rate is meaningfully above 0%, it means embedding-similarity's usefulness in this project depends entirely on it having seen attacks *like* the one it's catching -- it's a lookup against known patterns, not a general injection detector. That's a legitimate design (real threat-intel-based detection works this way too), but it means every genuinely novel attack family will be missed until a human adds an example of it to the corpus. Worth deciding explicitly whether that's an acceptable production trade-off, not something to discover after deployment.
