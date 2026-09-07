"""
Tests whether indexing our OWN corpus into the embedding-similarity known-bad
set (not just the public dataset) actually helps -- without leaking, unlike
the bug fixed in docs/leakage_fix.md.

This is the build doc's originally-intended design for this layer: "Embed
your red-team corpus... of known injection attempts... generalizes to
paraphrases of known attacks." That design assumes the known-bad set includes
attacks *like* the ones you're testing against -- which our public-dataset-only
index (0% detection, see docs/leakage_fix.md) doesn't provide, since
`verazuo/jailbreak_llms` is stylistically nothing like this project's
hand-written corpus.

The naive way to test this (index the full corpus, then test against the
full corpus) is exactly the leakage bug already found and fixed. The honest
way is leave-one-out: for each corpus case, fit the known-bad index on the
public dataset PLUS every OTHER corpus attack case (never the case being
tested), then check if that held-out case gets caught. Every test case is
genuinely unseen by its own index -- 36 separate fits, cheap for a
TF-IDF vectorizer on a small corpus.

This produces a legitimately different, non-leaked number from the
comparison table's 0%, because now the reference set has attacks from the
SAME style/distribution as the test case (just not that exact one) --
answering "does this layer generalize to novel variations of known attacks
from our own corpus," which is a fair question the public-dataset-only
number couldn't answer.
"""
import csv
import sys
from pathlib import Path

import yaml
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors.embedding_similarity import SIMILARITY_THRESHOLD

CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
TRAIN_PATH = REPO_ROOT / "data" / "train.csv"
OUT_PATH = REPO_ROOT / "docs" / "embedding_loo_result.md"


def load_public_known_bad():
    """Public dataset's known-bad (label=1) texts -- same ones the current
    production/eval embedding index uses, forming the baseline reference set
    every LOO fit also includes."""
    texts = []
    with open(TRAIN_PATH, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["label"] == "1":
                texts.append(row["text"])
    return texts


def load_corpus_cases():
    with open(CORPUS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_loo():
    public_known_bad = load_public_known_bad()
    cases = load_corpus_cases()

    results = []

    for i, case in enumerate(cases):
        text = case["payload"].strip()
        expected = case["expected_behavior"]

        # Known-bad reference set for THIS case's fit: public dataset +
        # every other corpus case's payload that's itself an attack
        # (block/flag), excluding the case under test entirely.
        other_known_bad = [
            c["payload"].strip() for j, c in enumerate(cases)
            if j != i and c["expected_behavior"] in ("block", "flag")
        ]
        known_bad_texts = public_known_bad + other_known_bad

        vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=20000, sublinear_tf=True)
        known_bad_vectors = vectorizer.fit_transform(known_bad_texts)

        query_vector = vectorizer.transform([text])
        similarity = cosine_similarity(query_vector, known_bad_vectors)[0].max()
        blocked = similarity >= SIMILARITY_THRESHOLD

        results.append({
            "id": case["id"], "category": case["category"], "expected": expected,
            "similarity": float(similarity), "blocked": bool(blocked),
        })

    return results


def score(results):
    should_block = [r for r in results if r["expected"] == "block"]
    should_allow = [r for r in results if r["expected"] == "allow"]

    detection_rate = sum(1 for r in should_block if r["blocked"]) / len(should_block) if should_block else 0.0
    fp_rate = sum(1 for r in should_allow if r["blocked"]) / len(should_allow) if should_allow else 0.0
    missed = [r["id"] for r in should_block if not r["blocked"]]
    false_positives = [r["id"] for r in should_allow if r["blocked"]]

    return detection_rate, fp_rate, missed, false_positives, len(should_block), len(should_allow)


def main():
    print("Running leave-one-out cross-validation (36 separate fits)...")
    results = run_loo()
    detection_rate, fp_rate, missed, false_positives, n_block, n_allow = score(results)

    print(f"\nLOO detection rate: {detection_rate:.0%} ({n_block - len(missed)}/{n_block})")
    print(f"LOO false-positive rate: {fp_rate:.0%} ({len(false_positives)}/{n_allow})")
    print(f"Missed: {missed}")
    print(f"False positives: {false_positives}")

    lines = [
        "# Embedding-Similarity: Leave-One-Out Cross-Validation Result\n",
        "Tests whether indexing our OWN corpus (not just the public dataset) into the",
        "embedding-similarity known-bad set helps, WITHOUT leaking -- each case is",
        "tested against an index built from every OTHER case, never itself. See this",
        "script's module docstring and `docs/leakage_fix.md` for why this methodology",
        "matters.\n",
        f"**LOO detection rate: {detection_rate:.0%} ({n_block - len(missed)}/{n_block})**",
        f"**LOO false-positive rate: {fp_rate:.0%} ({len(false_positives)}/{n_allow})**\n",
        f"Compare to the comparison table's honest public-dataset-only number: **0%**.\n",
        "## Missed even with LOO (novel enough that no other corpus example resembles them)\n",
    ]
    for case_id in missed:
        lines.append(f"- {case_id}")
    lines.append("\n## False positives under LOO\n")
    for case_id in false_positives:
        lines.append(f"- {case_id}")
    lines.append(
        "\n## What this means\n\n"
        "If LOO detection rate is meaningfully above 0%, it means embedding-similarity's "
        "usefulness in this project depends entirely on it having seen attacks *like* "
        "the one it's catching -- it's a lookup against known patterns, not a general "
        "injection detector. That's a legitimate design (real threat-intel-based "
        "detection works this way too), but it means every genuinely novel attack "
        "family will be missed until a human adds an example of it to the corpus. "
        "Worth deciding explicitly whether that's an acceptable production trade-off, "
        "not something to discover after deployment."
    )

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWritten to {OUT_PATH}")


if __name__ == "__main__":
    main()
