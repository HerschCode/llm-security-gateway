"""
L2 threshold sweep: find the precision/recall/F1 curve for each embedding backend
(TF-IDF and sentence_transformer) across the full eval corpus.

Answers the question "is L2 fundamentally useless or just mis-thresholded?" before
deciding whether to replace the layer or tune it.

Run from repo root:
    python scripts/threshold_sweep_l2.py

Outputs a per-threshold table for each backend, identifies the best threshold by F1
and by "max detection at 0% FP", and prints a per-category breakdown at the optimal
threshold for each backend.
"""
import csv
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector
from gateway.detectors.embedding_similarity_st import SentenceTransformerSimilarityDetector

EVAL_PATH = REPO_ROOT / "data" / "eval.csv"
THRESHOLDS = np.round(np.arange(0.05, 0.96, 0.05), 2).tolist()


def _load_yaml_rows():
    import yaml
    cases = yaml.safe_load(open(REPO_ROOT / "corpus" / "injection_cases.yaml", encoding="utf-8"))
    return [{"case_id": c["id"], "text": c.get("payload", c.get("text", "")), "category": c.get("category", ""),
             "expected_behavior": c.get("expected_behavior", "block")} for c in cases]


def load_eval():
    rows = _load_yaml_rows()  # canonical corpus; data/eval.csv is a stale derived export
    attack  = [r for r in rows if r["expected_behavior"] == "block"]
    legit   = [r for r in rows if r["expected_behavior"] == "allow"]
    flag    = [r for r in rows if r["expected_behavior"] == "flag"]
    return rows, attack, legit, flag


def score_at_threshold(detector, cases, threshold):
    """Returns (blocked_flags,) per case — boolean list."""
    return [detector.detect(r["text"], threshold=threshold).blocked for r in cases]


def f1(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0
    r = tp / (tp + fn) if (tp + fn) else 0
    return 2 * p * r / (p + r) if (p + r) else 0


def sweep(name, detector, attack, legit):
    print(f"\n{'='*60}")
    print(f"  {name} — threshold sweep")
    print(f"{'='*60}")
    print(f"  {'Threshold':>10}  {'Detection':>10}  {'FP rate':>8}  {'F1':>6}")
    print(f"  {'-'*10}  {'-'*10}  {'-'*8}  {'-'*6}")

    best_f1 = (-1, None)
    best_zero_fp = (-1, None)
    rows_out = []

    for t in THRESHOLDS:
        atk_blocked  = score_at_threshold(detector, attack, t)
        leg_blocked  = score_at_threshold(detector, legit, t)

        tp = sum(atk_blocked)
        fn = len(attack) - tp
        fp = sum(leg_blocked)
        tn = len(legit) - fp

        det  = tp / len(attack) if attack else 0
        fpr  = fp / len(legit)  if legit  else 0
        f1v  = f1(tp, fp, fn)

        print(f"  {t:>10.2f}  {tp}/{len(attack)} ({det:>5.1%})  {fp}/{len(legit)} ({fpr:>4.1%})  {f1v:.3f}")
        rows_out.append((t, det, fpr, f1v, tp, fp))

        if f1v > best_f1[0]:
            best_f1 = (f1v, t)
        if fpr == 0 and det > best_zero_fp[0]:
            best_zero_fp = (det, t)

    print(f"\n  Best F1 = {best_f1[0]:.3f} at threshold {best_f1[1]}")
    if best_zero_fp[1] is not None:
        print(f"  Best detection at 0% FP = {best_zero_fp[0]:.1%} at threshold {best_zero_fp[1]}")
    else:
        print(f"  No threshold achieves 0% FP")

    return best_f1[1], rows_out


def category_breakdown(name, detector, rows, threshold):
    print(f"\n  {name} @ threshold={threshold} — category breakdown")
    print(f"  {'Category':<26}  {'Block':>8}  {'Allow':>8}  {'Detection':>10}  {'FP rate':>8}")
    print(f"  {'-'*26}  {'-'*8}  {'-'*8}  {'-'*10}  {'-'*8}")

    cats = sorted({r["category"] for r in rows})
    for cat in cats:
        cat_rows = [r for r in rows if r["category"] == cat]
        atk  = [r for r in cat_rows if r["expected_behavior"] == "block"]
        leg  = [r for r in cat_rows if r["expected_behavior"] == "allow"]
        blocked_atk = [detector.detect(r["text"], threshold=threshold).blocked for r in atk]
        blocked_leg = [detector.detect(r["text"], threshold=threshold).blocked for r in leg]
        det = f"{sum(blocked_atk)}/{len(atk)}" if atk else "—"
        fpr = f"{sum(blocked_leg)}/{len(leg)}" if leg else "—"
        det_pct = f"({sum(blocked_atk)/len(atk):.0%})" if atk else ""
        fpr_pct = f"({sum(blocked_leg)/len(leg):.0%})" if leg else ""
        print(f"  {cat:<26}  {' ':>8}  {' ':>8}  {det} {det_pct:>6}  {fpr} {fpr_pct:>6}")


def main():
    rows, attack, legit, flag = load_eval()
    print(f"\nEval corpus: {len(rows)} cases  ({len(attack)} attack | {len(legit)} allow | {len(flag)} flag)")

    # --- TF-IDF ---
    tfidf = EmbeddingSimilarityDetector()
    tfidf.load()
    best_t_tfidf, _ = sweep("TF-IDF (L2 default)", tfidf, attack, legit)
    category_breakdown("TF-IDF", tfidf, rows, best_t_tfidf)

    # --- sentence_transformer ---
    st = SentenceTransformerSimilarityDetector()
    st.load()
    best_t_st, _ = sweep("sentence_transformer (L2 opt-in)", st, attack, legit)
    category_breakdown("sentence_transformer", st, rows, best_t_st)

    print("\n")


if __name__ == "__main__":
    main()
