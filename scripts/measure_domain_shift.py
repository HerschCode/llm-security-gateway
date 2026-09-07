"""
Documents a real before/after fix: the from-scratch classifier, trained only
on the public jailbreak_llms dataset (no in-domain data at all), had a much
higher false-positive rate on realistic in-domain (ops-assistant) benign
queries than our narrow attack-corpus eval revealed -- because that corpus's
few negative-control examples don't look like typical deployment traffic.

This script reconstructs a genuine "before" state (retrains explicitly
WITHOUT corpus/benign_indomain_queries.yaml's train split, via
prepare_training_data.py --exclude-indomain-benign), measures false-positive
rate on that file's held-out eval split, then retrains WITH the fix and
measures again -- writing the before/after result to docs/domain_shift_fix.md.
Both runs use the *same* held-out eval split, so the comparison is
apples-to-apples. (An earlier version of this script assumed "before" meant
"whatever model currently exists," which silently broke once the fix became
a permanent, unconditional part of the standard pipeline -- see the
--exclude-indomain-benign flag's docstring in prepare_training_data.py.)
"""
import csv
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

BENIGN_QUERIES_PATH = REPO_ROOT / "corpus" / "benign_indomain_queries.yaml"
CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
DOC_PATH = REPO_ROOT / "docs" / "domain_shift_fix.md"
MODEL_DIR = REPO_ROOT / "models" / "scratch_classifier"
MODEL_BACKUP_DIR = REPO_ROOT / "models" / "scratch_classifier_before_fix"


def load_benign_eval_texts():
    with open(BENIGN_QUERIES_PATH, encoding="utf-8") as f:
        cases = yaml.safe_load(f)
    return [c["text"] for c in cases if c["split"] == "eval"]


def measure_fp_rate(eval_texts):
    from gateway.detectors.classifier import ScratchClassifierDetector
    detector = ScratchClassifierDetector()
    detector.load()
    results = []
    for text in eval_texts:
        r = detector.detect(text)
        results.append((text, r.blocked, r.confidence))
    fp_count = sum(1 for _, blocked, _ in results if blocked)
    return fp_count, len(results), results


def main():
    eval_texts = load_benign_eval_texts()

    print("=== Regenerating training data WITHOUT in-domain benign examples (genuine 'before') ===")
    subprocess.run(
        [sys.executable, "scripts/prepare_training_data.py", "--exclude-indomain-benign"],
        cwd=REPO_ROOT, check=True,
    )
    print("\n=== Training the 'before' classifier ===")
    subprocess.run([sys.executable, "scripts/train_scratch_classifier.py"], cwd=REPO_ROOT, check=True)

    print("\n=== BEFORE: measuring FP rate (classifier trained WITHOUT the fix) ===")
    fp_before, n, results_before = measure_fp_rate(eval_texts)
    for text, blocked, conf in results_before:
        print(f"  {'BLOCKED' if blocked else 'allowed'} ({conf:.3f})  | {text}")
    print(f"False positive rate BEFORE fix: {fp_before}/{n} = {fp_before/n:.0%}\n")

    # Back up the "before" model so both numbers are independently reproducible.
    if MODEL_DIR.exists():
        if MODEL_BACKUP_DIR.exists():
            shutil.rmtree(MODEL_BACKUP_DIR)
        shutil.copytree(MODEL_DIR, MODEL_BACKUP_DIR)

    print("=== Regenerating training data WITH in-domain benign examples ===")
    subprocess.run([sys.executable, "scripts/prepare_training_data.py"], cwd=REPO_ROOT, check=True)

    print("\n=== Retraining classifier ===")
    subprocess.run([sys.executable, "scripts/train_scratch_classifier.py"], cwd=REPO_ROOT, check=True)

    print("\n=== AFTER: measuring FP rate with retrained classifier ===")
    fp_after, n2, results_after = measure_fp_rate(eval_texts)
    for text, blocked, conf in results_after:
        print(f"  {'BLOCKED' if blocked else 'allowed'} ({conf:.3f})  | {text}")
    print(f"False positive rate AFTER fix: {fp_after}/{n2} = {fp_after/n2:.0%}")

    # Re-run the main corpus evaluation too, to confirm the fix didn't regress
    # detection rate on actual attacks.
    print("\n=== Re-running scripts/evaluate.py to confirm no regression on attack detection ===")
    subprocess.run([sys.executable, "scripts/fit_embedding_detector.py"], cwd=REPO_ROOT, check=True)
    eval_output = subprocess.run(
        [sys.executable, "scripts/evaluate.py"], cwd=REPO_ROOT, check=True,
        capture_output=True, text=True,
    ).stdout

    # Corpus size and benign-example count computed fresh, not hardcoded --
    # an earlier version of this script hardcoded "20-case ... 2 benign
    # examples" directly into the narrative text below. That was accurate
    # when first written (corpus was 20 cases with 2 negative controls at the
    # time), but became silently wrong after the corpus was later expanded to
    # 36 cases with 4 negative controls -- rerunning this script would have
    # regenerated docs/domain_shift_fix.md with fresh FP-rate numbers glued
    # to a stale, incorrect narrative. Caught during an audit pass; fixed by
    # computing these counts from the corpus file instead of hardcoding them.
    with open(CORPUS_PATH, encoding="utf-8") as f:
        corpus_cases = yaml.safe_load(f)
    n_corpus_cases = len(corpus_cases)
    n_corpus_benign = sum(1 for c in corpus_cases if c["expected_behavior"] == "allow")
    n_indomain_train = sum(1 for q in yaml.safe_load(BENIGN_QUERIES_PATH.read_text(encoding="utf-8")) if q["split"] == "train")
    n_indomain_eval = len(eval_texts)

    doc_lines = [
        "# Domain-Mismatch False Positive: Before/After Fix\n",
        "## What happened",
        "The from-scratch classifier (Layer 3) was trained on the public",
        "`verazuo/jailbreak_llms` dataset (general ChatGPT/Reddit-style prompts) plus",
        f"our own {n_corpus_cases}-case attack corpus. Our corpus's eval set only contains",
        f"{n_corpus_benign} benign examples, and neither resembles typical ops-assistant",
        "deployment traffic, so",
        "the comparison table's 0% false-positive rate did not reveal a real problem:",
        "when tested against realistic business-assistant queries the model had",
        f"never seen, it blocked **{fp_before}/{n} ({fp_before/n:.0%})** of genuinely benign requests",
        '(discovered via manual smoke-testing, not the automated eval — see chat log).\n',
        "## The fix",
        "Added `corpus/benign_indomain_queries.yaml` — realistic ops-assistant",
        f"benign queries, split into {n_indomain_train} train / {n_indomain_eval} held-out eval. Mixed the",
        f"{n_indomain_train} train examples into `data/train.csv` as label=0 rows and retrained",
        "from scratch. The held-out eval examples were used to measure",
        "generalization, not just memorization, of the fix.\n",
        "## Result",
        f"False positive rate on held-out in-domain benign queries: **{fp_before}/{n} ({fp_before/n:.0%}) "
        f"before -> {fp_after}/{n2} ({fp_after/n2:.0%}) after**.\n",
        "## Per-query results (before)\n",
        "| Query | Blocked? | Confidence |",
        "|---|---|---|",
    ]
    for text, blocked, conf in results_before:
        doc_lines.append(f"| {text} | {'yes' if blocked else 'no'} | {conf:.3f} |")
    doc_lines.append("\n## Per-query results (after)\n")
    doc_lines.append("| Query | Blocked? | Confidence |")
    doc_lines.append("|---|---|---|")
    for text, blocked, conf in results_after:
        doc_lines.append(f"| {text} | {'yes' if blocked else 'no'} | {conf:.3f} |")
    doc_lines.append("\n## Confirming no regression on actual attack detection (re-ran scripts/evaluate.py)\n")
    doc_lines.append("```")
    doc_lines.append(eval_output.strip())
    doc_lines.append("```")
    doc_lines.append("\n## Lesson")
    doc_lines.append(
        "A narrow, attack-heavy eval corpus can look clean (0% FP rate) while hiding a "
        "much worse false-positive rate on realistic traffic, simply because the eval "
        "set didn't include enough of the *actual* benign distribution the gateway will "
        "see in production. Detection-rate numbers are only as trustworthy as the eval "
        "set's coverage of the true negative class, not just the true positive class."
    )

    DOC_PATH.write_text("\n".join(doc_lines) + "\n", encoding="utf-8")
    print(f"\nWritten to {DOC_PATH}")


if __name__ == "__main__":
    main()
