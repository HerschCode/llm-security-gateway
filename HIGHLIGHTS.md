# Engineering highlights

Eight moments from this build where checking a result mattered more than
producing one. Full running log: [`docs/decisions.md`](docs/decisions.md).

---

## 1. Caught my own train/test leakage — and reported the worse number

The embedding-similarity detector was scoring **97%** detection. Good number.
While sanity-checking three new Unicode-obfuscation cases, all three came back
with a cosine similarity of **exactly 1.000** — the tell for an exact string
match, not similarity.

**Root cause:** the corpus was being mixed into training using the *same
unmodified text* also used for evaluation. 30 of 36 cases had their payload
verbatim in `train.csv`. The detector was largely recognising its own answer key.

**Fix:** the corpus is now strictly held-out — zero training rows. Verified no
leakage programmatically before re-running anything.

**Honest result:** embedding-similarity, measured correctly, detects **0%** of
this corpus. Classifier dropped 87% → 50%. Every comparison table, red-team
report and README number was regenerated against the honest figures.

The gateway still works end-to-end (16/72 pass without it, 50/72 with it, on
the corpus as expanded 2026-09-12 — see `docs/corpus_expansion_result.md`) —
because that's the *ensemble* doing defense-in-depth, not any single layer being
excellent. That's a more realistic security story than the one the project was
telling before. → [`docs/leakage_fix.md`](docs/leakage_fix.md)

---

## 2. Found a documented security control that was silently dead code

`project2_agent`'s tool-authorization was described — in its own docs — as
scoping employees to "their own tickets/records only." It gated on a
`requester_id` parameter.

**Nothing in the system ever passed that parameter.** Traced the gap all the way
up: the router never included it in tool kwargs, `handle()` never accepted it,
and the entire gateway pipeline (`BackendAdapter`, `GatewayMiddleware`, the
FastAPI request model) only ever tracked a coarse role tier — never individual
identity.

**Verified before fixing:** any employee could escalate any other employee's
ticket.

**Fix:** threaded a `user_id` parameter through the whole chain — every adapter
signature, `process()` / `process_streaming()`, the request model. Re-verified
in-process and over live HTTP: an employee can act on their own ticket, is
refused for someone else's. The self-lookup test deliberately uses a *different*
employee than the router's default target, so a coincidental pass can't hide a
regression. → [`docs/decisions.md`](docs/decisions.md) ("Full audit pass")

---

## 3. A deterministic-looking pipeline that wasn't

`train_scratch_classifier.py` had `RANDOM_SEED = 42` right there in the code. It
seeded Python's `random`. It never called `torch.manual_seed()` — so weight init
and dropout were unseeded, and every training run produced a genuinely different
model.

**Found because** re-running the domain-shift measurement gave 40% where the doc
said 30%, from a supposedly identical process.

**Fix:** seed torch, CUDA, and the DataLoader's generator. **Verified by diffing
the actual `model.pt` bytes** across two runs — identical, not just "metrics
match."

**Consequence stated plainly:** the honest, now-reproducible detection rate is
**50%**, not the 63% reported earlier — a different number because it's a
different (now pinned) model, not a regression. Every percentage in the README
is tied to seed 42 on this exact code, and says so.

---

## 4. An external review said 36 test cases was too few. It was right.

Every false-positive rate in this README — 0% for the classifier, 0% for both
embedding backends — was measured against **4 negative controls.** Confirmed
correct as far as it went, and structurally incapable of catching anything a
4-example sample happens not to include.

**Fix:** wrote 36 more cases (72 total), 8 of them new negative controls
(4 → 12), each targeting a technique not already in the corpus rather than
padding the count. Re-ran everything — `scripts/evaluate.py`, both live
redteam reports, the LOO-CV experiment, the sentence-transformer and
DistilBERT comparisons.

**What the bigger sample actually found:** the classifier's real
false-positive rate is **25%, not 0%** — a benign self-lookup and a benign
"please decode this" request both trip it, at confidences of 0.52-0.53
(genuinely borderline, not a confident model failure). A rule-based pattern
(`base64[\s\-]?decode`) has the identical blind spot for the same reason.
Checked each one's actual confidence score rather than reporting "false
positive" as one undifferentiated bucket.

**Not patched reflexively** — the classifier's training process is unchanged;
this was a measurement gap, not a regression, and closing it properly (more
borderline benign training examples) is follow-up work, not a same-session
fix. → [`docs/corpus_expansion_result.md`](docs/corpus_expansion_result.md)

---

## 5. The best detector on my own data was not the one to ship

A pre-trained guard model (ProtectAI's DeBERTa) beats the from-scratch ensemble
on this project's own corpus: **80.8% vs 53.8%** detection. It is reported next
to the shipped default in the README, and so is the reason it is not the default:
704 MB does not fit the free 512 MB tier. Meta's Prompt Guard 2 was then
evaluated through a hosted API and, at a matched false-positive rate, did not beat
the shipped classifier either, so the hosted layer was **not built** and the
reasons (30 requests a minute, an availability dependency, prompts leaving the
box) are on record.

**A correction along the way:** the "needs 860 MB" figure in the docs was one
noisy measurement. Re-runs on the same machine gave +396 to +588 MB, and no
container test was ever run, so the docs now say the 512 MB fit is *inferred*.
→ [`docs/guard-baselines.md`](docs/guard-baselines.md)

---

## 6. I red-teamed my own gateway, and it had holes

garak, promptfoo, an LLM attacker and a deterministic mutation attacker produced
12 findings. Among them: a **stored XSS in the gateway's own dashboard**, and a
rate limiter that a client could reset by **changing a self-chosen session id**.
Seven are fixed and retested, two largely or partly fixed, and three are open,
each pinned by a test that records the current miss so it cannot be forgotten.

**The report needed the same scrutiny.** The MITRE ATLAS IDs had been written from
memory; they were checked against MITRE's data and the report now says when. The
raw JSON of one adaptive run was lost to my own `rm`; it was rerun, the free-tier
token quota ran out after 4 of 6 goals, and the tables show the rerun only,
labelled partial. → [`reports/redteam-2026-09.md`](reports/redteam-2026-09.md)

---

## 7. The evaluation found a bug in my own PII recognizer

Measuring the new Indian-identifier recognizers on a labelled set showed the
Aadhaar pattern matching the first three groups of a card-style 4-4-4-4 number:
**10% of 16-digit numbers that fail the Luhn check** (a checksum digit passes by
chance one time in ten). Fixed, with a regression test, and because the test
split had been consulted, a fresh set was written and used **once** for the final
numbers. Presidio, added as an option, turned out *not* to be more accurate on the
structured types, and its NER flagged 394 of 3,000 ordinary prompts, so it stays
optional. → [`docs/pii-evaluation.md`](docs/pii-evaluation.md)

---

## 8. Two bugs no scanner found

Writing the threat model turned up a missing request size limit and an email
pattern that took **270 ms on 20,000 characters** of `a` (quadratic). Both are
fixed, with a scaling test that fails on the old pattern. Separately, a `# nosec`
comment I put in the middle of a `Popen(...)` line turned its `stdin`/`stdout`/
`stderr` arguments into comment text: the file still parsed and Bandit was
satisfied. Only the MCP proxy test noticed, by **hanging**. It now has a test that
the pipes are set. → [`SECURITY.md`](SECURITY.md), [`docs/security-scans.md`](docs/security-scans.md)

---

### The through-line

Every one of these made a headline number *worse*, or found a flaw in my own work.
They're in the repo because a portfolio that only shows the good runs isn't showing
the part of the job that actually matters.
