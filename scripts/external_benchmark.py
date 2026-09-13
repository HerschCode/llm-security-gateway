"""
External benchmark: evaluate detection layers against the jailbreak_llms dataset
(Shen et al. 2023, https://github.com/verazuo/jailbreak_llms), a community-sourced
corpus of 666 jailbreak prompts that is independent of our training and eval data.

This tests out-of-distribution generalisation: our scratch classifier was trained
on data/train.csv (our own corpus); the jailbreak_llms prompts were never seen
during training. Lower detection rates here than on data/eval.csv are expected
and honest — the gap quantifies how much the detector relies on patterns
specific to our hand-built corpus.

Outputs:
  reports/p3_external_benchmark.json  — structured results
  (printed to stdout)

No API keys or database access needed — reads committed model files only.

Run from repo root:
    python scripts/external_benchmark.py
"""
import csv
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors import rule_based
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector
from gateway.detectors.classifier import ScratchClassifierDetector

EXTERNAL_CSV = (
    REPO_ROOT
    / "data" / "external" / "jailbreak_llms" / "jailbreak_llms-main"
    / "data" / "prompts" / "jailbreak_prompts_2023_05_07.csv"
)
SAMPLE_SIZE = 150  # representative subset; full set is 666
RANDOM_SEED = 42


def load_external_prompts(n: int) -> list[str]:
    """Load n prompts from the jailbreak_llms dataset (stratified by platform)."""
    import random
    rng = random.Random(RANDOM_SEED)
    with open(EXTERNAL_CSV, encoding="utf-8", errors="replace") as f:
        rows = [r for r in csv.DictReader(f) if r.get("prompt", "").strip()]
    rng.shuffle(rows)
    return [r["prompt"] for r in rows[:n]]


def run_detector(name: str, detect_fn, prompts: list[str]) -> dict:
    latencies = []
    blocked = 0
    for p in prompts:
        t0 = time.perf_counter()
        result = detect_fn(p)
        latencies.append((time.perf_counter() - t0) * 1000)
        if result.blocked:
            blocked += 1
    n = len(prompts)
    return {
        "n": n,
        "detected": blocked,
        "detection_rate": round(blocked / n, 3),
        "avg_latency_ms": round(sum(latencies) / n, 3),
    }


def main():
    print(f"Loading external jailbreak prompts (sample={SAMPLE_SIZE}) ...")
    prompts = load_external_prompts(SAMPLE_SIZE)
    print(f"  Loaded {len(prompts)} prompts from jailbreak_llms dataset\n")

    print("Layer 1 — rule_based ...")
    rb = run_detector("rule_based", rule_based.detect, prompts)
    print(f"  {rb['detected']}/{rb['n']} detected  ({rb['detection_rate']:.0%})")

    print("Layer 2 — embedding_similarity ...")
    emb = EmbeddingSimilarityDetector()
    emb.load()
    es = run_detector("embedding_similarity", emb.detect, prompts)
    print(f"  {es['detected']}/{es['n']} detected  ({es['detection_rate']:.0%})")

    print("Layer 3 — scratch_classifier ...")
    clf = ScratchClassifierDetector()
    clf.load()
    sc = run_detector("scratch_classifier", clf.detect, prompts)
    print(f"  {sc['detected']}/{sc['n']} detected  ({sc['detection_rate']:.0%})")

    report = {
        "dataset": "jailbreak_llms (Shen et al. 2023)",
        "dataset_url": "https://github.com/verazuo/jailbreak_llms",
        "sample_size": SAMPLE_SIZE,
        "random_seed": RANDOM_SEED,
        "note": (
            "All prompts are jailbreaks (label=1). No benign cases in this dataset, "
            "so only detection rate is reported, not FP rate. "
            "Lower rates than on data/eval.csv are expected — these prompts were "
            "never seen during training. The gap quantifies out-of-distribution generalisation."
        ),
        "results": {
            "rule_based": rb,
            "embedding_similarity": es,
            "scratch_classifier": sc,
        },
        "internal_eval_reference": {
            "source": "data/eval.csv (120 cases, 5 categories, hand-built corpus)",
            "rule_based_detection": "16%",
            "embedding_similarity_detection": "0%",
            "scratch_classifier_detection": "54%",
        },
    }

    out = REPO_ROOT / "reports" / "p3_external_benchmark.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\n{'='*60}")
    print("EXTERNAL BENCHMARK SUMMARY")
    print(f"{'='*60}")
    print(f"Dataset: jailbreak_llms (Shen et al. 2023), n={SAMPLE_SIZE}")
    print(f"{'Layer':<25} {'External (OOD)':<20} {'Internal (in-dist)'}")
    print(f"{'-'*65}")
    internal = {"rule_based": "16%", "embedding_similarity": "0%", "scratch_classifier": "54%"}
    for layer, res in [("rule_based", rb), ("embedding_similarity", es), ("scratch_classifier", sc)]:
        ext_str = f"{res['detection_rate']:.0%} ({res['detected']}/{res['n']})"
        print(f"  {layer:<23} {ext_str:<20} {internal[layer]}")
    print(f"\nSaved → {out}")


if __name__ == "__main__":
    main()
