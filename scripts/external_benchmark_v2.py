"""
Contamination-audited external benchmark.

Why this exists: scripts/external_benchmark.py scored the detectors on a sample of the
jailbreak_llms dataset and described it as "independent of our training data". It is not:
data/train.csv is itself built from jailbreak_llms (scripts/prepare_training_data.py), and
an exact-match audit (section A below) finds most of that "external" sample verbatim in the
training positives. Its 92%/97% figures therefore mostly measure memorisation.

This script (1) reports that overlap, (2) re-scores jailbreak_llms on only the prompts NOT
found in training, and (3) adds two datasets from unrelated authors:
  * deepset/prompt-injections (Hugging Face, cc-by-4.0): 662 labelled prompts (only the 116-row TEST split is scored, because the retrained classifier trains on its train split), both
    injections (label 1) and benign (label 0), some in German -- gives a false-positive rate.
  * JailbreakBench JBB-Behaviors "benign-behaviors" (100 borderline-but-benign requests):
    a hard false-positive set. (Its "harmful-behaviors" are plain harmful requests, not
    injection or jailbreak attempts, so they are out of scope for an injection detector and
    deliberately not scored as attacks.)

Overlap is checked by exact match after lowercasing and whitespace normalisation; near
duplicates (paraphrases, truncations) are NOT detected, so "clean" is a lower bound on
contamination, not proof of none.

Data (gitignored, download once):
  python -c "from huggingface_hub import snapshot_download as s; \
    s('deepset/prompt-injections',repo_type='dataset',local_dir='data/external/prompt-injections'); \
    s('JailbreakBench/JBB-Behaviors',repo_type='dataset',local_dir='data/external/JBB-Behaviors')"
Run:  python -X utf8 scripts/external_benchmark_v2.py
Writes reports/p3_external_benchmark_v2.json
"""
import csv
import json
import math
import re
import sys
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
csv.field_size_limit(10**9)

from gateway.detectors import rule_based  # noqa: E402
from gateway.detectors.classifier import ScratchClassifierDetector  # noqa: E402
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector  # noqa: E402

EXT = REPO_ROOT / "data" / "external"
JBLLMS = EXT / "jailbreak_llms/jailbreak_llms-main/data/prompts/jailbreak_prompts_2023_05_07.csv"
DEEPSET = EXT / "prompt-injections/data"
JBB_BENIGN = EXT / "JBB-Behaviors/data/benign-behaviors.csv"


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t.strip().lower())


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - h) / d, 3), round((c + h) / d, 3)]


def load_detectors():
    emb = EmbeddingSimilarityDetector(); emb.load()
    clf = ScratchClassifierDetector(); clf.load()
    return {"rule_based": rule_based.detect, "embedding_similarity": emb.detect, "scratch_classifier": clf.detect}


def score(detectors, texts):
    """Per-text blocked flags for each layer plus 'ensemble_any' (block-on-any-layer)."""
    flags = {k: [] for k in detectors}
    for t in texts:
        for k, fn in detectors.items():
            flags[k].append(bool(fn(t).blocked))
    flags["ensemble_any"] = [any(f[i] for f in [flags[k] for k in detectors]) for i in range(len(texts))]
    return flags


def rate_row(flags, n):
    return {k: {"blocked": sum(v), "n": n, "rate": round(sum(v) / n, 3), "ci95": wilson(sum(v), n)} for k, v in flags.items()}


def show(title, rows):
    print(f"\n{title}")
    for k, r in rows.items():
        print(f"  {k:<22} {r['blocked']:>4}/{r['n']:<4} {r['rate']:>6.1%}  95% CI [{r['ci95'][0]:.1%}, {r['ci95'][1]:.1%}]")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    train = list(csv.DictReader(open(REPO_ROOT / "data/train.csv", encoding="utf-8")))
    train_all = {norm(r["text"]) for r in train}
    train_pos = {norm(r["text"]) for r in train if r["label"] == "1"}
    corpus_payloads = {norm(c.get("payload", "")) for c in yaml.safe_load(open(REPO_ROOT / "corpus/injection_cases.yaml", encoding="utf-8"))}
    detectors = load_detectors()
    report = {"detectors": list(detectors), "overlap_method": "exact match after lowercase + whitespace normalisation (near-duplicates not detected)"}

    # A + B: jailbreak_llms contamination audit and clean-subset rescoring
    jb = [r["prompt"] for r in csv.DictReader(open(JBLLMS, encoding="utf-8", errors="replace")) if r.get("prompt", "").strip()]
    contaminated = [p for p in jb if norm(p) in train_pos]
    clean = [p for p in jb if norm(p) not in train_pos]
    print(f"A. jailbreak_llms (2023-05-07): {len(jb)} prompts; {len(contaminated)} ({len(contaminated)/len(jb):.0%}) are verbatim in data/train.csv positives; {len(clean)} not found")
    report["A_contamination"] = {"jailbreak_llms_prompts": len(jb), "exact_in_train_positives": len(contaminated), "not_found_in_train": len(clean)}
    fl_c = score(detectors, contaminated); show("   scored on the CONTAMINATED prompts (memorisation, not generalisation)", rate_row(fl_c, len(contaminated)))
    fl_k = score(detectors, clean); show("B. scored on the CLEAN jailbreak_llms prompts (not found in training; detection only)", rate_row(fl_k, len(clean)))
    report["A_contaminated_scores"] = rate_row(fl_c, len(contaminated))
    report["B_jailbreak_llms_clean"] = rate_row(fl_k, len(clean))

    # C: deepset/prompt-injections
    import pandas as pd
    # TEST split only: the retrained classifier (scripts/retrain_classifier_v2.py) trains on deepset's TRAIN split
    ds = pd.read_parquet(next(DEEPSET.glob("test-*.parquet")))
    ds["n"] = ds["text"].map(norm)
    overlap_train = ds["n"].isin(train_all)
    overlap_corpus = ds["n"].isin(corpus_payloads)
    keep = ds[~overlap_train & ~overlap_corpus].drop_duplicates("n")
    print(f"\nC. deepset/prompt-injections: {len(ds)} rows; removed {int(overlap_train.sum())} in train.csv, {int(overlap_corpus.sum())} in our corpus, then de-duplicated -> {len(keep)} scored")
    report["C_deepset"] = {"rows": len(ds), "removed_in_train": int(overlap_train.sum()), "removed_in_corpus": int(overlap_corpus.sum()), "scored": len(keep)}
    for label, name in ((1, "injections (label 1): detection rate"), (0, "benign (label 0): false-positive rate")):
        texts = keep.loc[keep["label"] == label, "text"].tolist()
        fl = score(detectors, texts); rows = rate_row(fl, len(texts))
        show(f"   {name}, n={len(texts)}", rows)
        report["C_deepset"]["injection_detection" if label else "benign_false_positive"] = rows

    # D: JBB benign behaviours
    jbb = [r["Goal"] for r in csv.DictReader(open(JBB_BENIGN, encoding="utf-8"))]
    fl = score(detectors, jbb); rows = rate_row(fl, len(jbb))
    show(f"D. JailbreakBench benign-behaviors: false-positive rate, n={len(jbb)}", rows)
    report["D_jbb_benign_false_positive"] = rows

    out = REPO_ROOT / "reports" / "p3_external_benchmark_v2.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
