"""
Runs all three detection layers against data/eval.csv (our 20-case corpus, held
out from the layers' own fitting/training) and produces:
  - per-case pass/fail per layer, written back into corpus/injection_cases.yaml's
    observed_behavior/status fields (per-layer, since each layer can differ)
  - a comparison table: detection rate, false-positive rate, latency, saved to
    docs/comparison_table.md and printed to stdout

Detection rate here = recall on cases where expected_behavior != "allow".
False-positive rate = block rate on cases where expected_behavior == "allow".
The single "flag" case (GW-018) is reported separately, not folded into either
rate, since neither block nor allow is strictly "correct" for it -- that's the
point of including an ambiguous case (see corpus notes on GW-018).
"""
import csv
import sys
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors import rule_based
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector
from gateway.detectors.classifier import ScratchClassifierDetector

CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
EVAL_PATH = REPO_ROOT / "data" / "eval.csv"
COMPARISON_TABLE_PATH = REPO_ROOT / "docs" / "comparison_table.md"


def load_eval_cases():
    with open(EVAL_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def run_layer(name, detect_fn, cases):
    """Runs one detector against every case, returns per-case results + timing."""
    results = []
    for case in cases:
        result = detect_fn(case["text"])
        results.append({
            "case_id": case["case_id"],
            "category": case["category"],
            "expected_behavior": case["expected_behavior"],
            "blocked": result.blocked,
            "confidence": result.confidence,
            "matched_pattern_id": result.matched_pattern_id,
            "latency_ms": result.latency_ms,
        })
    return results


def score(results):
    """Computes detection rate, false-positive rate, avg latency, excluding the
    'flag' case from both rate calculations (reported separately)."""
    should_block = [r for r in results if r["expected_behavior"] == "block"]
    should_allow = [r for r in results if r["expected_behavior"] == "allow"]
    ambiguous = [r for r in results if r["expected_behavior"] == "flag"]

    detection_rate = (
        sum(1 for r in should_block if r["blocked"]) / len(should_block)
        if should_block else float("nan")
    )
    false_positive_rate = (
        sum(1 for r in should_allow if r["blocked"]) / len(should_allow)
        if should_allow else float("nan")
    )
    avg_latency_ms = sum(r["latency_ms"] for r in results) / len(results)

    missed = [r for r in should_block if not r["blocked"]]
    false_positives = [r for r in should_allow if r["blocked"]]

    return {
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "avg_latency_ms": avg_latency_ms,
        "n_should_block": len(should_block),
        "n_should_allow": len(should_allow),
        "n_ambiguous": len(ambiguous),
        "missed_case_ids": [r["case_id"] for r in missed],
        "false_positive_case_ids": [r["case_id"] for r in false_positives],
        "ambiguous_case_ids_and_decisions": [(r["case_id"], r["blocked"]) for r in ambiguous],
    }


def score_by_category(all_results: dict) -> dict:
    """Per-category detection rate for each layer.

    Only counts cases where expected_behavior == 'block' (attack cases).
    Benign and ambiguous cases are excluded — there aren't enough per category
    to make a FP rate meaningful at this corpus size.
    """
    layers = list(all_results.keys())
    # Collect categories from any layer (all layers see the same cases)
    categories = sorted(set(r["category"] for r in next(iter(all_results.values()))))

    per_cat = {}
    for cat in categories:
        per_cat[cat] = {}
        for layer in layers:
            cat_attack = [
                r for r in all_results[layer]
                if r["category"] == cat and r["expected_behavior"] == "block"
            ]
            if not cat_attack:
                per_cat[cat][layer] = None
                continue
            detected = sum(1 for r in cat_attack if r["blocked"])
            per_cat[cat][layer] = {
                "n": len(cat_attack),
                "detected": detected,
                "detection_rate": round(detected / len(cat_attack), 3),
            }
    return per_cat


def update_corpus_observed_behavior(all_layer_results: dict):
    """Writes observed_behavior/status back into the corpus YAML, per layer,
    so the corpus file itself carries a record of what was actually observed --
    not just what's claimed in a README table.

    Preserves the file's leading '#' comment header across the rewrite:
    yaml.dump() does not preserve comments, and this bit the project twice
    already (see docs/decisions.md) before this fix -- the header was
    manually re-added by hand after being silently stripped. Automating it
    here so it can't happen a third time."""
    with open(CORPUS_PATH, encoding="utf-8") as f:
        original_lines = f.readlines()

    header_lines = []
    for line in original_lines:
        if line.startswith("#") or line.strip() == "":
            header_lines.append(line)
        else:
            break
    header_text = "".join(header_lines)

    with open(CORPUS_PATH, encoding="utf-8") as f:
        cases = yaml.safe_load(f)

    by_id = {c["id"]: c for c in cases}

    for layer_name, results in all_layer_results.items():
        for r in results:
            case = by_id.get(r["case_id"])
            if case is None:
                continue
            observed = "block" if r["blocked"] else "allow"
            case.setdefault("observed_behavior_by_layer", {})[layer_name] = observed
            expected = case["expected_behavior"]
            passed = (observed == expected) or (expected == "flag")
            case.setdefault("status_by_layer", {})[layer_name] = "pass" if passed else "fail"

    body_text = yaml.dump(cases, sort_keys=False, allow_unicode=True, width=88)

    with open(CORPUS_PATH, "w", encoding="utf-8") as f:
        f.write(header_text + body_text)


def main():
    cases = load_eval_cases()
    print(f"Loaded {len(cases)} eval cases from {EVAL_PATH}\n")

    # --- Layer 1: rule-based ---
    layer1_results = run_layer("rule_based", rule_based.detect, cases)

    # --- Layer 2: embedding similarity ---
    embed_detector = EmbeddingSimilarityDetector()
    embed_detector.load()
    layer2_results = run_layer("embedding_similarity", embed_detector.detect, cases)

    # --- Layer 3: from-scratch classifier ---
    clf_detector = ScratchClassifierDetector()
    clf_detector.load()
    layer3_results = run_layer("scratch_classifier", clf_detector.detect, cases)

    all_results = {
        "rule_based": layer1_results,
        "embedding_similarity": layer2_results,
        "scratch_classifier": layer3_results,
    }

    scores = {name: score(results) for name, results in all_results.items()}
    per_cat = score_by_category(all_results)

    # --- Print + write comparison table ---
    lines = []
    lines.append("# Detection Layer Comparison\n")
    lines.append(f"Evaluated against `data/eval.csv` — our own {len(cases)}-case red-team")
    lines.append("corpus, held out from each layer's fitting/training. Numbers below are")
    lines.append("from an actual run of `scripts/evaluate.py`, not estimated.\n")
    lines.append("| Layer | Detection rate | False-positive rate | Avg latency (ms) |")
    lines.append("|---|---|---|---|")
    for name in ["rule_based", "embedding_similarity", "scratch_classifier"]:
        s = scores[name]
        lines.append(
            f"| {name} | {s['detection_rate']:.0%} ({s['n_should_block'] - len(s['missed_case_ids'])}/{s['n_should_block']}) "
            f"| {s['false_positive_rate']:.0%} ({len(s['false_positive_case_ids'])}/{s['n_should_allow']}) "
            f"| {s['avg_latency_ms']:.3f} |"
        )
    lines.append("")
    lines.append("## Per-category detection rates (attack cases only)\n")
    layer_names = ["rule_based", "embedding_similarity", "scratch_classifier"]
    header = "| Category (n attacks) | " + " | ".join(layer_names) + " |"
    sep = "|---|" + "---|" * len(layer_names)
    lines.append(header)
    lines.append(sep)
    for cat, cat_scores in per_cat.items():
        n = next(
            (v["n"] for v in cat_scores.values() if v is not None), "?"
        )
        row_cells = []
        for layer in layer_names:
            v = cat_scores.get(layer)
            if v is None:
                row_cells.append("—")
            else:
                row_cells.append(f"{v['detection_rate']:.0%} ({v['detected']}/{v['n']})")
        lines.append(f"| {cat} ({n}) | " + " | ".join(row_cells) + " |")
    lines.append("")
    lines.append("## Missed attacks (should have blocked, didn't)\n")
    for name in ["rule_based", "embedding_similarity", "scratch_classifier"]:
        missed = scores[name]["missed_case_ids"]
        lines.append(f"- **{name}**: {', '.join(missed) if missed else '(none)'}")
    lines.append("")
    lines.append("## False positives (should have allowed, blocked)\n")
    for name in ["rule_based", "embedding_similarity", "scratch_classifier"]:
        fps = scores[name]["false_positive_case_ids"]
        lines.append(f"- **{name}**: {', '.join(fps) if fps else '(none)'}")
    lines.append("")
    lines.append("## Ambiguous case (GW-018, expected_behavior=flag) — reported separately\n")
    for name in ["rule_based", "embedding_similarity", "scratch_classifier"]:
        decisions = scores[name]["ambiguous_case_ids_and_decisions"]
        rendered = ", ".join(f"{cid}={'blocked' if b else 'allowed'}" for cid, b in decisions)
        lines.append(f"- **{name}**: {rendered}")

    table_text = "\n".join(lines)
    print(table_text)

    COMPARISON_TABLE_PATH.write_text(table_text + "\n", encoding="utf-8")
    print(f"\nWritten to {COMPARISON_TABLE_PATH}")

    update_corpus_observed_behavior(all_results)
    print(f"Corpus observed_behavior/status fields updated in {CORPUS_PATH}")


if __name__ == "__main__":
    main()
