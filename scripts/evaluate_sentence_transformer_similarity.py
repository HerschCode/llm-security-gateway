"""
Tests the build doc's ORIGINAL layer-2 design for real: transformer sentence
embeddings (all-MiniLM-L6-v2) + cosine similarity, instead of the TF-IDF
substitution gateway/detectors/embedding_similarity.py has used since
2026-09-05 (documented there as a stand-in for exactly this, blocked at the
time by no model-hub access -- see docs/decisions.md).

That access now works from this environment (huggingface.co reachable, see
docs/decisions.md 2026-09-11 DistilBERT entries) -- so, following the same
"don't leave a flagged hypothesis untested" discipline that applied to the
DistilBERT script, this actually measures it instead of continuing to assume
sentence-transformers "would obviously do better."

Same known-bad index (data/train.csv, label==1), same corpus, same threshold-
sweep methodology as the TF-IDF layer, so the comparison is apples-to-apples:
this script also sweeps a small set of thresholds and reports the best one
found on the corpus, rather than reusing TF-IDF's 0.35 (cosine similarity
scores from a different embedding space aren't comparable to that number).

Usage: python scripts/evaluate_sentence_transformer_similarity.py
"""
import csv
import json
import sys
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
THRESHOLDS_TO_SWEEP = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]


def load_known_bad():
    texts, ids = [], []
    with open(REPO_ROOT / "data" / "train.csv", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if row["label"] == "1":
                texts.append(row["text"])
                ids.append(f"TRAIN-{i}")
    return texts, ids


def load_corpus():
    with open(REPO_ROOT / "corpus" / "injection_cases.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np

    print(f"Loading {MODEL_NAME} (downloads ~90MB on first run)...")
    model = SentenceTransformer(MODEL_NAME)

    known_bad_texts, known_bad_ids = load_known_bad()
    print(f"Encoding {len(known_bad_texts)} known-bad examples...")
    t0 = time.perf_counter()
    known_bad_vecs = model.encode(known_bad_texts, batch_size=64, show_progress_bar=False,
                                   convert_to_numpy=True, normalize_embeddings=True)
    index_time_s = time.perf_counter() - t0

    corpus = load_corpus()

    def score_at_threshold(threshold: float):
        detection_tp = detection_total = 0
        fp = fp_total = 0
        latencies = []
        missed, false_positives = [], []
        flag_results = {}
        for case in corpus:
            text = case["payload"]
            expected = case["expected_behavior"]
            t0 = time.perf_counter()
            qvec = model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
            sims = cosine_similarity(qvec, known_bad_vecs)[0]
            best = float(sims.max())
            latencies.append((time.perf_counter() - t0) * 1000)
            blocked = best >= threshold

            if expected == "block":
                detection_total += 1
                if blocked:
                    detection_tp += 1
                else:
                    missed.append(case["id"])
            elif expected == "allow":
                fp_total += 1
                if blocked:
                    fp += 1
                    false_positives.append(case["id"])
            elif expected == "flag":
                flag_results[case["id"]] = blocked

        return {
            "threshold": threshold,
            "detection_rate": detection_tp / detection_total if detection_total else 0,
            "detection_fraction": f"{detection_tp}/{detection_total}",
            "false_positive_rate": fp / fp_total if fp_total else 0,
            "false_positive_fraction": f"{fp}/{fp_total}",
            "avg_latency_ms": sum(latencies) / len(latencies),
            "missed": missed,
            "false_positives": false_positives,
            "flag_results": flag_results,
        }

    print(f"Sweeping {len(THRESHOLDS_TO_SWEEP)} thresholds on the corpus "
          f"(index built in {index_time_s:.1f}s over {len(known_bad_texts)} examples)...")
    results = [score_at_threshold(t) for t in THRESHOLDS_TO_SWEEP]

    # Best = highest detection rate among thresholds with false_positive_rate == 0,
    # same selection principle the TF-IDF layer's 0.35 was picked under (see
    # docs/decisions.md) -- not just whichever threshold posts the biggest number.
    zero_fp = [r for r in results if r["false_positive_rate"] == 0]
    best = max(zero_fp, key=lambda r: r["detection_rate"]) if zero_fp else \
        max(results, key=lambda r: r["detection_rate"] - r["false_positive_rate"])

    print("\n=== Threshold sweep ===")
    for r in results:
        print(f"  threshold={r['threshold']:.2f}  detect={r['detection_fraction']:>6} "
              f"({r['detection_rate']:.0%})  fp={r['false_positive_fraction']} "
              f"({r['false_positive_rate']:.0%})")

    print(f"\n=== Best (highest detection at 0% FP): threshold={best['threshold']} ===")
    print(f"detection_rate={best['detection_rate']:.2%} ({best['detection_fraction']})")
    print(f"false_positive_rate={best['false_positive_rate']:.2%} ({best['false_positive_fraction']})")
    print(f"avg_latency_ms={best['avg_latency_ms']:.3f}")
    print(f"missed={best['missed']}")
    print(f"false_positives={best['false_positives']}")
    print(f"flag_results={best['flag_results']}")

    out = {
        "model": MODEL_NAME, "index_size": len(known_bad_texts),
        "index_build_time_s": index_time_s, "sweep": results, "best": best,
    }
    out_path = REPO_ROOT / "docs" / "sentence_transformer_similarity_raw_result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"\nRaw result written to {out_path}")


if __name__ == "__main__":
    main()
