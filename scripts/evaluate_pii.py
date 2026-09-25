"""
Compare PII backends on labeled data. Run from the environment that has the [pii] extra (a venv with presidio-analyzer, presidio-anonymizer,
spaCy and en_core_web_sm); the regex systems need nothing. Writes reports/p5_pii_evaluation.json.

Systems
  regex_us              the patterns that shipped before Phase 5 (US formats only)
  regex                 + SSA validity rules for SSNs and the dependency-free Indian identifiers of gateway/pii_in.py (the new default)
  presidio_default      Presidio's own recognizers only (no Indian ones), blank spaCy pipeline
  presidio_builtin_in   + Presidio's own InAadhaarRecognizer / InPanRecognizer
  presidio              + the custom Indian recognizers (gateway/pii_presidio.py)
  presidio_ner          the same with en_core_web_sm, which adds PERSON

Data
  corpus/pii_labeled.jsonl  synthetic, seeded, with dev/test halves and hard-negative groups (scripts/build_pii_eval.py). The Presidio score
                            threshold is chosen on DEV only; everything reported as the result is TEST.
  Gretel (--external)       gretelai/synthetic_pii_finance_multilingual, English test split, Apache-2.0, independent of this repo's author. Only the
                            types both label: email, phone, ssn, credit card, person names. Download: see docs/pii-evaluation.md.
  benign texts              3,000 alpaca/dolly instructions: how often each system finds "PII" in ordinary text.

Matching is span-level: a prediction is a true positive if it has the same type as a gold span and overlaps it with IoU >= 0.5.
Run: python -X utf8 -m scripts.evaluate_pii [--external] [--out reports/p5_pii_evaluation.json]
"""
import argparse
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway import pii as pii_mod  # noqa: E402

TYPES = ["email", "phone", "credit_card", "ssn", "aadhaar", "pan", "person"]
STRUCTURED = [t for t in TYPES if t != "person"]
GRETEL_MAP = {"email": "email", "phone_number": "phone", "ssn": "ssn", "credit_card_number": "credit_card", "name": "person", "first_name": "person", "last_name": "person"}
SYSTEMS = ["regex_us", "regex", "presidio_default", "presidio_builtin_in", "presidio", "presidio_ner"]


def predict(system: str, text: str, threshold: float | None = None) -> list[tuple[str, int, int]]:
    if system in ("regex_us", "regex"):
        spans = pii_mod.detect_spans_regex(text, extended=system == "regex")
    else:
        from gateway import pii_presidio as pp
        cfg = {"presidio_default": dict(ner=False, custom_indian=False, builtin_indian=False),
               "presidio_builtin_in": dict(ner=False, custom_indian=False, builtin_indian=True),
               "presidio": dict(ner=False, custom_indian=True, builtin_indian=False),
               "presidio_ner": dict(ner=True, custom_indian=True, builtin_indian=False)}[system]
        spans = pp.detect_spans_presidio(text, threshold=threshold, **cfg)
    return [(s.type, s.start, s.end) for s in pii_mod.resolve_overlaps(spans)]


def iou(a0, a1, b0, b1) -> float:
    inter = max(0, min(a1, b1) - max(a0, b0))
    union = (a1 - a0) + (b1 - b0) - inter
    return inter / union if union else 0.0


def score(records, preds):
    """preds: parallel list of predicted (type, start, end). Returns per-type counts, per-group recall/alarm rates."""
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    grp = defaultdict(lambda: {"n": 0, "gold": 0, "hit": 0, "records_with_alarm": 0})
    for r, pr in zip(records, preds):
        gold = [(s["type"], s["start"], s["end"]) for s in r["spans"]]
        used = set()
        g = grp[r["group"]]
        g["n"] += 1
        g["gold"] += len(gold)
        for gt, g0, g1 in gold:
            hit = next((i for i, (pt, p0, p1) in enumerate(pr) if i not in used and pt == gt and iou(g0, g1, p0, p1) >= 0.5), None)
            if hit is None:
                fn[gt] += 1
            else:
                used.add(hit)
                tp[gt] += 1
                g["hit"] += 1
        for i, (pt, _, _) in enumerate(pr):
            if i not in used:
                fp[pt] += 1
        if not gold and pr:
            g["records_with_alarm"] += 1
    return tp, fp, fn, dict(grp)


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if (p is not None and r is not None) else None)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": None if p is None else round(p, 3), "recall": None if r is None else round(r, 3), "f1": None if f is None else round(f, 3)}


def summarize(records, preds, types=TYPES):
    tp, fp, fn, grp = score(records, preds)
    per_type = {t: prf(tp[t], fp[t], fn[t]) for t in types}
    micro = prf(sum(tp[t] for t in STRUCTURED), sum(fp[t] for t in STRUCTURED), sum(fn[t] for t in STRUCTURED))
    micro_all = prf(sum(tp[t] for t in types), sum(fp[t] for t in types), sum(fn[t] for t in types))
    return {"per_type": per_type, "micro_structured": micro, "micro_all": micro_all,
            "groups": {g: {"n": v["n"], "recall": round(v["hit"] / v["gold"], 3) if v["gold"] else None,
                           "alarm_rate": round(v["records_with_alarm"] / v["n"], 3) if not v["gold"] else None} for g, v in grp.items()}}


def load_labeled():
    return [json.loads(line) for line in open(REPO_ROOT / "corpus" / "pii_labeled.jsonl", encoding="utf-8")]


def available(system: str) -> bool:
    if system.startswith("presidio"):
        try:
            import presidio_analyzer  # noqa: F401
            if system == "presidio_ner":
                import spacy
                spacy.load("en_core_web_sm")
        except Exception:                          # noqa: BLE001 -- any import/model problem means "not available here"
            return False
    return True


def sweep_threshold(dev, system):
    """Dev-only: the Presidio score threshold with the best micro F1 on the structured types."""
    best = None
    rows = {}
    for t in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9):
        preds = [predict(system, r["text"], t) for r in dev]
        s = summarize(dev, preds)["micro_structured"]
        rows[str(t)] = {"precision": s["precision"], "recall": s["recall"], "f1": s["f1"]}
        if best is None or (s["f1"] or 0) >= best[1]:                  # ties go to the higher (more conservative) threshold
            best = (t, s["f1"] or 0)
    return best[0], rows


def external_gretel(systems, threshold_by_system, limit=None):
    import pandas as pd
    p = REPO_ROOT / "data" / "external" / "gretel_pii" / "data" / "English_test-00000-of-00001.parquet"
    if not p.exists():
        return {"status": "not_run", "reason": f"{p} is missing"}
    df = pd.read_parquet(p)
    recs = []
    for text, spans in zip(df["generated_text"], df["pii_spans"]):
        gold = [{"type": GRETEL_MAP[s["label"]], "start": s["start"], "end": s["end"]} for s in (json.loads(spans) if isinstance(spans, str) else spans) if s["label"] in GRETEL_MAP]
        recs.append({"group": "gretel", "text": text, "spans": gold})
    if limit:
        recs = recs[:limit]
    ext_types = ["email", "phone", "ssn", "credit_card", "person"]
    out = {"documents": len(recs), "gold_spans": {t: sum(1 for r in recs for s in r["spans"] if s["type"] == t) for t in ext_types}, "systems": {}}
    for system in systems:
        preds = [[x for x in predict(system, r["text"], threshold_by_system.get(system)) if x[0] in ext_types] for r in recs]
        s = summarize(recs, preds, ext_types)
        out["systems"][system] = {"per_type": s["per_type"]}
    return out


def benign_false_positives(systems, threshold_by_system):
    rng = random.Random(7)
    alpaca = json.load(open(REPO_ROOT / "data/external/alpaca-cleaned/alpaca_data_cleaned.json", encoding="utf-8"))
    dolly = [json.loads(line) for line in open(REPO_ROOT / "data/external/databricks-dolly-15k/databricks-dolly-15k.jsonl", encoding="utf-8")]
    texts = [a["instruction"] + (" " + a["input"] if a["input"] else "") for a in rng.sample(alpaca, 1500)] + [d["instruction"] for d in rng.sample(dolly, 1500)]
    out = {"texts": len(texts), "systems": {}}
    for system in systems:
        flagged = []
        for t in texts:
            spans = predict(system, t, threshold_by_system.get(system))
            if spans:
                flagged.append((t[:90], sorted({s[0] for s in spans})))
        out["systems"][system] = {"texts_with_any_span": len(flagged), "examples": flagged[:5]}
    return out


def latency(systems, records, threshold_by_system):
    sample = random.Random(3).sample(records, 300)
    out = {}
    for system in systems:
        predict(system, sample[0]["text"], threshold_by_system.get(system))            # warm-up (engine construction is not per-call cost)
        ms = []
        for r in sample:
            t0 = time.perf_counter()
            predict(system, r["text"], threshold_by_system.get(system))
            ms.append((time.perf_counter() - t0) * 1000)
        ms.sort()
        out[system] = {"p50_ms": round(ms[len(ms) // 2], 3), "p95_ms": round(ms[int(len(ms) * 0.95)], 3)}
    return out


def rss_child(system: str):
    """Print incremental RSS (MB) of building `system` and analysing one text, in a fresh process."""
    import psutil
    proc = psutil.Process()
    before = proc.memory_info().rss
    predict(system, "Call +91 98765 43210 or mail a.b@example.com, PAN ABCPE1234F, Priya Sharma in Mumbai")
    print(round((proc.memory_info().rss - before) / 2**20, 1))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO_ROOT / "reports" / "p5_pii_evaluation.json"))
    ap.add_argument("--external", action="store_true", help="also evaluate on the Gretel English test split (needs pandas + the downloaded parquet)")
    ap.add_argument("--fresh", action="store_true", help="also score corpus/pii_labeled_fresh.jsonl (written after the recognizers were frozen; report once, do not tune)")
    ap.add_argument("--rss", metavar="SYSTEM", help="internal: print incremental RSS of one system and exit")
    args = ap.parse_args()
    if args.rss:
        rss_child(args.rss)
        return

    import subprocess
    records = load_labeled()
    dev = [r for r in records if r["split"] == "dev"]
    test = [r for r in records if r["split"] == "test"]
    systems = [s for s in SYSTEMS if available(s)]
    skipped = [s for s in SYSTEMS if s not in systems]
    result = {"records": {"dev": len(dev), "test": len(test)}, "systems_run": systems, "systems_skipped": skipped, "threshold_sweep_dev": {}, "threshold": {}, "labeled": {}}

    thresholds = {}
    for system in systems:
        if system.startswith("presidio"):
            thresholds[system], result["threshold_sweep_dev"][system] = sweep_threshold(dev, system)
    result["threshold"] = thresholds
    for system in systems:
        for name, subset in (("dev", dev), ("test", test)):
            preds = [predict(system, r["text"], thresholds.get(system)) for r in subset]
            result["labeled"].setdefault(system, {})[name] = summarize(subset, preds)
    if args.fresh:
        fresh = [json.loads(line) for line in open(REPO_ROOT / "corpus" / "pii_labeled_fresh.jsonl", encoding="utf-8")]
        result["fresh"] = {"records": len(fresh)}
        for system in systems:
            result["fresh"][system] = summarize(fresh, [predict(system, r["text"], thresholds.get(system)) for r in fresh])
    result["latency"] = latency(systems, records, thresholds)
    result["rss_mb"] = {}
    for system in systems:
        try:
            out = subprocess.check_output([sys.executable, "-X", "utf8", "-m", "scripts.evaluate_pii", "--rss", system], text=True, cwd=REPO_ROOT, stderr=subprocess.DEVNULL)
            result["rss_mb"][system] = float(out.strip().splitlines()[-1])
        except Exception as exc:                   # noqa: BLE001
            result["rss_mb"][system] = f"failed: {type(exc).__name__}"
    result["benign"] = benign_false_positives(systems, thresholds)
    if args.external:
        result["external_gretel"] = external_gretel(systems, thresholds)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    def cell(m):
        return "n/a" if m["recall"] is None and m["precision"] is None else f"P {m['precision'] if m['precision'] is not None else '-'} R {m['recall'] if m['recall'] is not None else '-'}"
    print("threshold (chosen on dev):", thresholds)
    print(f"\n{'system':<22}{'structured micro P/R/F1 (test)':<36}{'person':<22}{'p50 ms':<9}{'RSS MB'}")
    for s in systems:
        t = result["labeled"][s]["test"]
        m = t["micro_structured"]
        print(f"{s:<22}{str(m['precision']) + ' / ' + str(m['recall']) + ' / ' + str(m['f1']):<36}{cell(t['per_type']['person']):<22}{result['latency'][s]['p50_ms']:<9}{result['rss_mb'][s]}")
    if args.fresh:
        print("\nFRESH set (structured micro P/R/F1):", {s: (result["fresh"][s]["micro_structured"]["precision"], result["fresh"][s]["micro_structured"]["recall"], result["fresh"][s]["micro_structured"]["f1"]) for s in systems})
    print("\nbenign texts with any span:", {s: v["texts_with_any_span"] for s, v in result["benign"]["systems"].items()}, "of", result["benign"]["texts"])
    print("wrote", args.out)


if __name__ == "__main__":
    main()
