"""
Prepare labeled training data for the embedding-similarity and from-scratch
classifier layers.

Sources combined:
  1. verazuo/jailbreak_llms (public, GitHub-hosted, MIT licensed) — bulk volume.
     jailbreak_prompts_2023_12_25.csv -> label 1 (malicious/jailbreak)
     regular_prompts_2023_12_25.csv   -> label 0 (benign)
     Downloaded automatically on first run (see download_jailbreak_llms() below)
     into data/external/jailbreak_llms/, cached there for subsequent runs.
  2. corpus/benign_indomain_queries.yaml (split=train half) — in-domain benign
     examples added after the domain-mismatch false-positive fix (see
     docs/domain_shift_fix.md).

  corpus/injection_cases.yaml (our own 36 hand-built attack cases) is NOT
  mixed into training -- it's strictly held-out eval data. An earlier version
  of this script did mix it in, which caused the train/test leakage documented
  in docs/leakage_fix.md. Fixed; do not reintroduce this.

Output:
  data/train.csv   -> text,label  (public dataset sample + in-domain benign queries)
  data/eval.csv    -> text,label,case_id,category,expected_behavior  (our corpus, fully held out)
"""
import csv
import random
import sys
import tarfile
import urllib.request
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
JBLLMS_CACHE_DIR = REPO_ROOT / "data" / "external" / "jailbreak_llms"
JBLLMS_TARBALL_URL = "https://codeload.github.com/verazuo/jailbreak_llms/tar.gz/refs/heads/main"
CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
BENIGN_QUERIES_PATH = REPO_ROOT / "corpus" / "benign_indomain_queries.yaml"
OUT_DIR = REPO_ROOT / "data"

RANDOM_SEED = 42
N_JAILBREAK_SAMPLE = 1000     # cap; jailbreak_llms only has 1405 total anyway
N_BENIGN_SAMPLE = 1000        # balance classes; regular set has 13735 available


def safe_extract(tar: tarfile.TarFile, dest: Path):
    """Extract only regular files and directories that stay inside `dest`. A hostile tarball can otherwise write anywhere with `../` or absolute
    member names, or plant links that later members are written through (CVE-2007-4559; Bandit B202)."""
    root = dest.resolve()
    members = tar.getmembers()
    for member in members:
        target = (root / member.name).resolve()
        if target != root and root not in target.parents:
            raise SystemExit(f"refusing to extract {member.name!r}: it would leave {root}")
        if not (member.isreg() or member.isdir()):
            raise SystemExit(f"refusing to extract {member.name!r}: links and special files are not allowed")
    tar.extractall(root, members=members)  # nosec B202 - every member was validated above


def download_jailbreak_llms() -> Path:
    """Downloads and extracts verazuo/jailbreak_llms into a repo-relative
    cache directory if not already present. Fixes a real portability bug:
    an earlier version of this function hardcoded a path specific to the
    environment this project was originally built in
    (/home/dev/jbllms/...), which does not exist on any other machine --
    running this script after cloning the repo would fail immediately with
    FileNotFoundError. Caught during an audit pass; this is the fix."""
    prompts_dir = JBLLMS_CACHE_DIR / "jailbreak_llms-main" / "data" / "prompts"
    if prompts_dir.exists():
        return prompts_dir

    print(f"jailbreak_llms not found in cache -- downloading from {JBLLMS_TARBALL_URL} ...")
    JBLLMS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tarball_path = JBLLMS_CACHE_DIR / "jailbreak_llms.tar.gz"

    if not JBLLMS_TARBALL_URL.startswith("https://"):
        raise SystemExit(f"refusing to download over a non-https URL: {JBLLMS_TARBALL_URL}")
    try:
        urllib.request.urlretrieve(JBLLMS_TARBALL_URL, tarball_path)  # nosec B310 - https only, checked above
    except Exception as e:
        raise SystemExit(
            f"Failed to download jailbreak_llms dataset from {JBLLMS_TARBALL_URL}: {e}\n"
            f"This script needs network access to github.com/codeload.github.com. "
            f"If you're behind a restrictive proxy/firewall, download the repo manually "
            f"and place its contents under {JBLLMS_CACHE_DIR}."
        )

    with tarfile.open(tarball_path) as tar:
        safe_extract(tar, JBLLMS_CACHE_DIR)
    tarball_path.unlink()

    if not prompts_dir.exists():
        raise SystemExit(f"Download succeeded but expected path not found: {prompts_dir}")

    print(f"Downloaded and cached to {JBLLMS_CACHE_DIR}")
    return prompts_dir


def load_public_dataset():
    prompts_dir = download_jailbreak_llms()
    jb_path = prompts_dir / "jailbreak_prompts_2023_12_25.csv"
    benign_path = prompts_dir / "regular_prompts_2023_12_25.csv"

    rng = random.Random(RANDOM_SEED)

    with open(jb_path, encoding="utf-8") as f:
        jb_rows = [row["prompt"] for row in csv.DictReader(f) if row.get("prompt")]
    with open(benign_path, encoding="utf-8") as f:
        benign_rows = [row["prompt"] for row in csv.DictReader(f) if row.get("prompt")]

    rng.shuffle(jb_rows)
    rng.shuffle(benign_rows)

    jb_sample = jb_rows[:N_JAILBREAK_SAMPLE]
    benign_sample = benign_rows[:N_BENIGN_SAMPLE]

    rows = [(t, 1) for t in jb_sample] + [(t, 0) for t in benign_sample]
    rng.shuffle(rows)
    return rows


def load_our_corpus():
    """Returns our corpus purely as held-out eval data -- NOT mixed into
    training. See docs/decisions.md, 2026-09-05 'train/test leakage found and
    fixed' entry: an earlier version of this function also returned a
    train_rows list that got mixed into data/train.csv, and because 30/36
    corpus cases' payloads are used verbatim (unchanged) as both that training
    signal AND the eval text, the embedding-similarity and classifier layers
    were partly being tested on exact-match memorization of their own eval
    set, not generalization. Fixed by removing the corpus's contribution to
    training entirely -- training now comes only from the public dataset and
    the in-domain benign queries, and the full 36-case corpus is genuinely
    never seen before scripts/evaluate.py runs."""
    with open(CORPUS_PATH, encoding="utf-8") as f:
        cases = yaml.safe_load(f)

    eval_rows = []
    for c in cases:
        label = 0 if c["expected_behavior"] == "allow" else 1
        full_payload = c["payload"].strip()
        eval_rows.append((full_payload, label, c["id"], c["category"], c["expected_behavior"]))

    return eval_rows


def load_indomain_benign_train_rows(exclude: bool = False):
    """Loads the split=train half of corpus/benign_indomain_queries.yaml, if it
    exists. Added after discovering the classifier's real-world false-positive
    rate on ops-assistant-style queries was much worse than the narrow attack
    corpus eval revealed -- see scripts/measure_domain_shift.py and
    docs/domain_shift_fix.md. Optional (skipped if file doesn't exist yet) so
    this script still works standalone before that fix was added.

    exclude=True deliberately skips this file even if it exists -- needed so
    scripts/measure_domain_shift.py can reconstruct a genuine "before the fix"
    training set on demand. Without this, that script had no way to produce a
    real "before" baseline once this function became a permanent, unconditional
    part of the pipeline: found during an audit pass when a rerun of the
    before/after comparison came back byte-identical in both directions,
    because "before" was silently using the same (already-fixed) data as
    "after." This flag exists specifically to make that comparison honest and
    re-runnable, not just a one-time historical artifact."""
    if exclude or not BENIGN_QUERIES_PATH.exists():
        return []
    with open(BENIGN_QUERIES_PATH, encoding="utf-8") as f:
        queries = yaml.safe_load(f)
    return [(q["text"], 0) for q in queries if q["split"] == "train"]


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--exclude-indomain-benign", action="store_true",
                         help="Skip mixing in-domain benign queries into training "
                              "(used by scripts/measure_domain_shift.py to reconstruct "
                              "a genuine pre-fix baseline; not for normal use)")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    public_rows = load_public_dataset()
    eval_rows = load_our_corpus()
    indomain_benign_rows = load_indomain_benign_train_rows(exclude=args.exclude_indomain_benign)

    all_train_rows = public_rows + indomain_benign_rows
    random.Random(RANDOM_SEED).shuffle(all_train_rows)

    train_path = OUT_DIR / "train.csv"
    with open(train_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        for text, label in all_train_rows:
            w.writerow([text, label])

    eval_path = OUT_DIR / "eval.csv"
    with open(eval_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "case_id", "category", "expected_behavior"])
        for text, label, case_id, category, expected in eval_rows:
            w.writerow([text, label, case_id, category, expected])

    print(f"Train set: {len(all_train_rows)} rows -> {train_path}")
    print(f"  public dataset: {len(public_rows)}  |  in-domain benign (mixed in): {len(indomain_benign_rows)}")
    print(f"  (our corpus: 0 rows in training -- held out entirely, see load_our_corpus() docstring)")
    print(f"Eval set: {len(eval_rows)} rows -> {eval_path}  (our corpus, held out for scoring)")


if __name__ == "__main__":
    main()
