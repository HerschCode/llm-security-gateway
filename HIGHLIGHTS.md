# Engineering highlights

Three moments from this build where checking a result mattered more than
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

The gateway still works end-to-end (6/36 pass without it, ~29/36 with it) —
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

### The through-line

Every one of these made a headline number *worse*. They're in the repo because a
portfolio that only shows the good runs isn't showing the part of the job that
actually matters.
