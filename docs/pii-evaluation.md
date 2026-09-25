# PII detection: regex, Presidio and pseudonymization (Phase 5)

**Question.** Should the gateway's PII step stay a handful of regexes, or move to Microsoft Presidio, and does Presidio handle Indian identifiers (Aadhaar,
PAN, Indian phone numbers) that the regexes never covered? Measured, not argued: `python -X utf8 -m scripts.evaluate_pii --external --fresh` (needs the optional
extra, see below). Raw output: [`reports/p5_pii_evaluation.json`](../reports/p5_pii_evaluation.json).

## What was built

| Piece | What it is |
|---|---|
| `gateway/pii_in.py` | Dependency-free Indian identifiers. **Aadhaar**: 12 digits, first digit 2-9; redacted when written 4-4-4 with a valid Verhoeff check digit, or when a context word ("aadhaar", "uid", ...) is near (then the checksum is not required); a bare 12-digit run with neither is left alone. **PAN**: `AAAAA9999A` with a valid holder-status fourth letter (lower case needs a "PAN" context). **Phone**: `+91` / `91` / `0` prefix, or 5-5 grouping, or a bare 10-digit number only with a context word; STD landlines need the leading 0 and a separator. |
| `gateway/pii.py` | One span-based path for every backend. `PII_BACKEND=regex` (default: US patterns, SSA validity rules for SSNs, the Indian identifiers), `regex_us` (exactly what shipped before, kept as the baseline), `presidio`, `presidio_ner`. Overlaps are resolved by validator strength; redaction is shared. |
| `gateway/pii_presidio.py` | The optional Presidio backend: Presidio's engine, registry and anonymizer, with three **custom `EntityRecognizer`s** for the Indian identifiers. They call the same tested functions as the regex path, so on those three types Presidio-with-custom equals the regex path by construction; what the comparison isolates is Presidio's *own* recognizers for email, phone, card and SSN, and its NER. Presidio's own India recognizers are also measured. |
| `gateway/pseudonymize.py` | Reversible pseudonymization, described below. |
| `[pii]` extra | `pip install -e .[pii]` (Presidio, spaCy, phonenumbers) and `python -m spacy download en_core_web_sm` for NER. Not used by the free-tier deploy or by CI's core path; the Presidio tests skip when it is absent. |

## How it was measured

- **A labeled set with hard negatives**: `corpus/pii_labeled.jsonl` (736 synthetic records, seeded, split into dev and test) built by `scripts/build_pii_eval.py`.
  No free labeled set covers Aadhaar/PAN, so the values are generated to be valid by construction (Luhn, Verhoeff, the PAN letter scheme, the SSA rules). **The recognizers and this
  generator have the same author**, so scores on it flatter the identifiers the author thought of. Mitigations: groups written to hurt (order numbers, checksum-valid
  tracking numbers, PAN-shaped SKUs, impossible SSN areas), groups where recall is *expected* to be low (bare numbers with no context word) reported rather than hidden, and the two sets below.
- **Tuning discipline**: the Presidio score threshold was chosen on dev only (ties go to the higher, more conservative value): 0.4 for every Presidio variant.
  The dev/test halves were then consulted, which exposed one bug (an Aadhaar match inside a card-style 4-4-4-4 number, 10% of Luhn-failing 16-digit numbers) and one weakness (SSNs with
  impossible areas): both were fixed, and because the test split had been seen, **the final numbers below are on a fresh set**, `corpus/pii_labeled_fresh.jsonl`, written after the fix with new
  values, new sentence templates (structured text, several identifiers per record, Hinglish, all-caps) and a different seed, and used once.
- **An independent set**: Gretel's `synthetic_pii_finance_multilingual`, English test split (2,891 documents, Apache-2.0, written by someone else). It labels only email, phone, SSN, card
  and names, so it says nothing about Indian identifiers. Its labels are incomplete (many unlabeled emails and numbers), so treat its precision figures as a lower bound and compare systems, not absolutes.
- **Benign text**: 3,000 ordinary instructions (alpaca and dolly): how often does each system find "PII" in text that has none worth redacting.
- Span-level matching, IoU >= 0.5 against a gold span of the same type. Small samples: differences of a few points are noise.

## Results

Fresh set (599 records; P / R = precision / recall over the six structured types; person is scored separately):

| System | Structured P / R | F1 | Person P / R | Benign texts flagged | p50 latency | Extra RSS |
|---|---|---|---|---|---|---|
| regex, before Phase 5 | 0.88 / 0.33 | 0.48 | not detected | 0 of 3000 | 0.005 ms | 0.0 MB |
| **regex + Indian identifiers (default)** | 0.97 / 0.92 | 0.94 | not detected | 0 of 3000 | 0.015 ms | 0.0 MB |
| Presidio, its own recognizers | 0.87 / 0.56 | 0.68 | not detected | 0 of 3000 | 0.411 ms | 85.1 MB |
| Presidio + its built-in India recognizers | 0.85 / 0.95 | 0.90 | not detected | 0 of 3000 | 0.474 ms | 85.5 MB |
| Presidio + custom Indian recognizers | 0.90 / 0.93 | 0.91 | not detected | 0 of 3000 | 0.463 ms | 85.4 MB |
| Presidio + custom + spaCy NER | 0.90 / 0.93 | 0.91 | 0.76 / 0.83 | 394 of 3000 | 4.11 ms | 123.8 MB |

Latency and memory are noisy on this machine (two runs of the same code gave p50 0.015 to 0.06 ms for the regex path and 0.4 to 1.9 ms for Presidio); the ratios, not the digits, are the finding.

Per type on the same fresh set (precision / recall):

| Type (gold spans) | regex, before Phase 5 | regex + Indian identifiers (default) | Presidio, its own recognizers | Presidio + its built-in India recognizers | Presidio + custom Indian recognizers |
|---|---|---|---|---|---|
| email (60) | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| phone (152) | 1.00 / 0.24 | 1.00 / 0.88 | 0.83 / 0.96 | 0.83 / 0.95 | 0.83 / 0.94 |
| credit_card (30) | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 0.90 | 1.00 / 0.90 | 1.00 / 0.90 |
| ssn (25) | 0.56 / 1.00 | 1.00 / 1.00 | 0.73 / 1.00 | 0.73 / 1.00 | 0.73 / 1.00 |
| aadhaar (117) | n/a / 0.00 | 0.97 / 0.87 | n/a / 0.00 | 0.78 / 0.90 | 0.97 / 0.87 |
| pan (77) | n/a / 0.00 | 0.90 / 0.94 | n/a / 0.00 | 0.91 / 1.00 | 0.90 / 0.94 |

What each system wrongly flags (share of hard-negative records with any false alarm, fresh set):

| Hard-negative group (share of records wrongly flagged) | regex, before Phase 5 | regex + Indian identifiers (default) | Presidio, its own recognizers | Presidio + its built-in India recognizers | Presidio + custom Indian recognizers |
|---|---|---|---|---|---|
| 10-digit order / AWB numbers starting 6-9 | 0% | 0% | 100% | 100% | 100% |
| 12-digit tracking numbers whose Verhoeff check happens to pass | 0% | 0% | 0% | 100% | 0% |
| 16-digit numbers that fail Luhn, written 4-4-4-4 | 0% | 0% | 0% | 20% | 0% |
| SSN-shaped part numbers with an impossible area (000, 666, 9xx) | 100% | 0% | 45% | 45% | 45% |
| PAN-shaped codes with an invalid holder-status letter | 0% | 0% | 0% | 0% | 0% |
| SKUs that are exactly PAN-shaped (a hazard nothing can resolve) | 0% | 100% | 0% | 100% | 100% |
| company and place names | 0% | 0% | 0% | 0% | 0% |
| plain text with numbers, versions, dates | 0% | 0% | 0% | 0% | 0% |

Where recall is low **by design** (the trade for not redacting order numbers), and how the identifiers cope when five appear together:

| Recall on | regex + Indian identifiers (default) | Presidio, its own recognizers | Presidio + its built-in India recognizers | Presidio + custom Indian recognizers |
|---|---|---|---|---|
| bare 10-digit mobile, with a context word | 100% | 100% | 100% | 100% |
| bare 10-digit mobile, no context word | 0% | 100% | 100% | 100% |
| bare 12-digit Aadhaar, context word | 100% | 0% | 100% | 100% |
| bare 12-digit Aadhaar, no context word | 0% | 0% | 100% | 0% |
| grouped 4-4-4 Aadhaar, valid checksum, no context word | 100% | 0% | 100% | 100% |
| Aadhaar with a bad checksum, context word | 100% | 0% | 0% | 100% |
| lower-case PAN, context word | 100% | 0% | 100% | 100% |
| lower-case PAN, no context word | 0% | 0% | 100% | 0% |
| records with 5 identifiers each (share of gold spans found) | 78% | 40% | 79% | 78% |

Independent check on Gretel (precision / recall; labels incomplete):

| Type (gold spans) | regex before | **regex + Indian (default)** | Presidio (patterns) | Presidio + NER |
|---|---|---|---|---|
| email (330) | 0.37 / 0.92 | 0.37 / 0.92 | 0.37 / 0.90 | 0.37 / 0.90 |
| phone (480) | 0.79 / 0.58 | 0.80 / 0.61 | 0.26 / 0.78 | 0.26 / 0.78 |
| ssn (85) | 0.94 / 0.87 | 0.95 / 0.85 | 0.94 / 0.75 | 0.94 / 0.75 |
| credit_card (83) | 0.61 / 0.52 | 0.61 / 0.52 | 0.81 / 0.40 | 0.81 / 0.40 |
| person (3730) | n/a / 0.00 | n/a / 0.00 | n/a / 0.00 | 0.37 / 0.60 |

On the main set's dev/test halves the picture is the same (test, structured F1: regex 0.93, Presidio + custom 0.91); the fresh set is the number to quote.

## Reading

1. **On my own data the extended regex path is the best detector** (fresh F1 0.94 against 0.91 for Presidio with the same Indian recognizers, and 0.48 for what shipped before), almost
   entirely on precision: Presidio's phone recogniser flags every 10-digit order number that starts with 6-9, and its SSN check still passes about half of the impossible-area part numbers. That
   result is **not independent** (same author), which is why the Gretel set is there, and it is mixed: the regex has far higher phone precision (0.80 vs 0.26)
   and better SSN, but lower phone recall (0.61 vs 0.78: the `phonenumbers` library knows international formats the regexes do not) and lower card precision.
   Both are weak on Gretel's card numbers (formats and labels differ from mine).
2. **Presidio's real contribution here is breadth, not accuracy on the structured types**: a phone-number library, and NER for names. Its price is 85.4 MB more resident memory (about 123.8 MB with the NER
   model) and roughly 30x the latency of the regexes, on a 512 MB free tier that already runs the injection classifier.
3. **NER for names is not usable as a default.** Person names are the one thing the regexes cannot find. `presidio_ner` finds them (fresh set P / R 0.76 / 0.83; Gretel 0.37 / 0.60) but
   flags 394 of 3,000 ordinary instructions (13%), mostly first names in example sentences, and tags words like "Aadhaar" as a person. Redacting those would change or break a large share
   of normal requests. It is offered as an opt-in for deployments that must not forward names.
4. **The gating is a policy choice with a measured price.** Presidio's own Aadhaar recogniser catches bare 12-digit numbers with no context (recall 100%) but flags **every** checksum-valid tracking number
   (100%), because about 8% of random 12-digit numbers pass the Verhoeff check. The custom rule redacts a bare Aadhaar only next to a context word,
   so it misses the bare-and-unlabelled case (0% recall) and does not flag tracking numbers. The same trade holds for bare mobile numbers and lower-case PANs. Order numbers being redacted
   before the backend sees them is exactly what RT-09 found, so precision was chosen; a deployment that prefers recall can lower the gates.
5. **Format-only PAN rules cannot separate a PAN from a PAN-shaped SKU** (all systems flag the exact-shape SKUs); nothing here resolves that without a real registry lookup.
6. **Bugs the evaluation found in my own code**: an Aadhaar match inside the first three groups of a card-style 4-4-4-4 number (now guarded, with a regression test), and SSNs with impossible areas
   (000, 666, 9xx) redacted as SSNs (the pre-Phase-5 patterns did so on every such part number; Presidio does not, and the extended regex now applies the SSA rules).

## Reversible pseudonymization (`PII_MODE=pseudonymize`)

Instead of `[REDACTED_EMAIL]`, PII becomes a stable per-session token such as `<<EMAIL_1_a3f9c2>>`; the model can still reason about identity ("the same address twice") without seeing the value,
and the response is detokenized for roles in `PII_DETOKENIZE_ROLES` (default `manager,admin`); other roles keep the tokens. Streaming holds back a token that is split across chunks, so no partial token is emitted.

Properties (tests: `tests/test_pseudonymize.py`): originals live only in process memory (never in the log, which records types only, and never on disk); tokens carry a per-session random nonce, so a token from another
session or a forged one does not resolve; a session remembers which `user_id` created it and another `user_id` does not get values back; a per-session value cap falls back to plain redaction, sessions are capped and expire.

Limits: the gateway does not authenticate principals, so `user_id`, `role` and `session_id` are asserted by the caller. The `user_id` binding catches mix-ups; it does **not** stop a caller who spoofs both a session id and a
user id and asks a backend that keeps per-session history to echo tokens. The vault is in memory, so it does not survive a restart or span instances. Responses are not scanned for PII the backend produced on its own.

## Decision

**The default stays the regex path, now with the Indian identifiers and SSN validity rules** (dependency-free, 0.94 F1 on the fresh set against 0.48 before, no false alarms on 3,000 benign instructions, about
0.015-0.06 ms). Presidio is available as an optional backend for deployments that want its phone-number coverage, and `presidio_ner` for names, with the costs above stated. Presidio was **not** made the default because
it is not more accurate on the structured types here, costs memory the free tier does not have to spare, and its NER would redact a large share of ordinary prompts. Not done: other Indian identifiers (passport, voter ID, GSTIN, vehicle
registration, which Presidio's built-ins also cover), non-English names, addresses and dates of birth, PII in *responses*, and any evaluation on real (non-synthetic) Indian data.

Reproduce: `python -m venv .venv-pii && .venv-pii/Scripts/python -m pip install presidio-analyzer presidio-anonymizer pandas pyarrow psutil pyyaml && .venv-pii/Scripts/python -m spacy download en_core_web_sm`, download the
Gretel English test parquet to `data/external/gretel_pii/data/`, then `python -X utf8 -m scripts.evaluate_pii --external --fresh`. The regex systems need nothing installed.
