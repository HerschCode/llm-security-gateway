"""
Paraphrase robustness test for the LLM Security Gateway.

Answers: "Does the classifier detect rephrased attacks, or does it just pattern-match
the training corpus verbatim?" — the distinction between generalization and memorization.

For each attack case in eval.csv, we apply three surface-level transformations:
  1. case_swap   — alternating UPPER/lower case (common evasion technique)
  2. space_insert — inserting zero-width spaces between characters (U+200B) to break
                   tokenization while keeping the text visually identical
  3. synonym_sub — substituting key trigger words with common synonyms
                   (e.g. "ignore" → "disregard", "instructions" → "directives")

These are NOT full paraphrases; they are the weakest possible perturbations.
If the model fails on case_swap or space_insert, that's a real robustness gap
because the semantic intent is identical — only the surface form changed.

Outputs:
  - Per-transformation detection rate and F1
  - Per-category breakdown
  - Side-by-side comparison with original eval.csv performance

Run from repo root:
    python scripts/paraphrase_robustness.py
"""
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.middleware import EMBEDDING_BACKEND
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector
from gateway.detectors.embedding_similarity_st import SentenceTransformerSimilarityDetector
import gateway.detectors.rule_based as _rule_based_module
from gateway.detectors.classifier_numpy import ScratchClassifierDetectorNumpy
from gateway.text_normalizer import normalize as _normalize

EVAL_PATH = REPO_ROOT / "data" / "eval.csv"

# Synonym substitution table — high-frequency trigger words in attack text
SYNONYMS = {
    "ignore": ["disregard", "bypass", "skip", "override"],
    "instructions": ["directives", "guidelines", "commands", "rules"],
    "previous": ["prior", "earlier", "former", "past"],
    "system": ["framework", "platform", "setup", "infrastructure"],
    "prompt": ["instruction", "directive", "command", "input"],
    "restrictions": ["limitations", "constraints", "limits", "boundaries"],
    "filters": ["safeguards", "controls", "checks", "barriers"],
    "admin": ["administrator", "superuser", "operator", "privileged user"],
    "disable": ["turn off", "deactivate", "remove", "suspend"],
    "unrestricted": ["unlimited", "unconstrained", "unfiltered", "free"],
}


def case_swap(text: str) -> str:
    """Alternate upper/lower case per character, leaving non-alpha unchanged."""
    result = []
    upper = True
    for ch in text:
        if ch.isalpha():
            result.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            result.append(ch)
    return "".join(result)


def space_insert(text: str) -> str:
    """Insert zero-width space (U+200B) between every character in attack keywords.
    Applies only to words > 4 chars to keep readability; short words like 'and'
    would look identical and confuse the output."""
    ZWSP = "​"
    words = text.split()
    result = []
    for word in words:
        if len(word) > 4:
            result.append(ZWSP.join(word))
        else:
            result.append(word)
    return " ".join(result)


def synonym_sub(text: str) -> str:
    """Replace first occurrence of each synonym-table key with its first synonym."""
    result = text
    for trigger, replacements in SYNONYMS.items():
        if trigger in result.lower():
            start = result.lower().index(trigger)
            # Preserve original capitalisation of first letter
            replacement = replacements[0]
            if result[start].isupper():
                replacement = replacement.capitalize()
            result = result[:start] + replacement + result[start + len(trigger):]
    return result


TRANSFORMS = {
    "original": lambda t: t,
    "case_swap": case_swap,
    "space_insert": space_insert,
    "synonym_sub": synonym_sub,
}


def f1(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0
    r = tp / (tp + fn) if (tp + fn) else 0
    return 2 * p * r / (p + r) if (p + r) else 0


def evaluate_detector(name: str, detector, attack_cases: list, transform_name: str, transform_fn):
    blocked = [detector.detect(transform_fn(r["text"])).blocked for r in attack_cases]
    tp = sum(blocked)
    fn = len(attack_cases) - tp
    det = tp / len(attack_cases) if attack_cases else 0
    return {"transform": transform_name, "detector": name, "detection": det, "tp": tp, "fn": fn}


def main():
    rows = list(csv.DictReader(open(EVAL_PATH, encoding="utf-8")))
    attack = [r for r in rows if r["expected_behavior"] == "block"]

    print(f"\n{'='*70}")
    print(f"  Paraphrase Robustness — {len(attack)} attack cases, 4 transforms")
    print(f"  EMBEDDING_BACKEND: {EMBEDDING_BACKEND}")
    print(f"{'='*70}")

    # Load all three real detectors.
    # rule_based is a module of functions (not a class), wrapped here for uniform interface.
    class _RuleBasedWrapper:
        def detect(self, text: str, **_):
            return _rule_based_module.detect(text)

    detectors = {"rule_based": _RuleBasedWrapper()}

    if EMBEDDING_BACKEND == "sentence_transformer":
        emb = SentenceTransformerSimilarityDetector()
    else:
        emb = EmbeddingSimilarityDetector()
    emb.load()
    detectors[f"embedding_{EMBEDDING_BACKEND}"] = emb

    clf = ScratchClassifierDetectorNumpy()
    clf.load()
    detectors["scratch_classifier"] = clf

    # Per-transform, per-detector detection rate
    print(f"\n  {'Transform':<14}  {'rule_based':>10}  {'embedding':>10}  {'classifier':>10}")
    print(f"  {'-'*14}  {'-'*10}  {'-'*10}  {'-'*10}")

    transform_results = {}
    for tname, tfn in TRANSFORMS.items():
        row = {}
        for dname, det in detectors.items():
            blocked = [det.detect(tfn(r["text"])).blocked for r in attack]
            rate = sum(blocked) / len(attack)
            row[dname] = rate
        transform_results[tname] = row

        dnames = list(detectors.keys())
        print(f"  {tname:<14}  {row[dnames[0]]:>9.1%}  {row[dnames[1]]:>10.1%}  {row[dnames[2]]:>10.1%}")

    # Delta vs original
    print(f"\n  Delta from original (negative = detection drop):")
    orig = transform_results["original"]
    for tname in ["case_swap", "space_insert", "synonym_sub"]:
        row = transform_results[tname]
        dnames = list(detectors.keys())
        deltas = [row[d] - orig[d] for d in dnames]
        print(f"  {tname:<14}  {deltas[0]:>+9.1%}  {deltas[1]:>+10.1%}  {deltas[2]:>+10.1%}")

    # --- Normalizer fix verification ---
    # Re-run space_insert with text_normalizer applied first (same as middleware).
    print(f"\n  space_insert WITH text_normalizer (middleware path):")
    print(f"  {'Detector':<20}  {'No norm':>8}  {'Norm':>8}  {'Delta':>8}")
    print(f"  {'-'*20}  {'-'*8}  {'-'*8}  {'-'*8}")
    dnames = list(detectors.keys())
    for dname, det in detectors.items():
        no_norm = transform_results["space_insert"][dname]
        with_norm = sum(det.detect(_normalize(space_insert(r["text"]))).blocked for r in attack) / len(attack)
        print(f"  {dname:<20}  {no_norm:>7.1%}  {with_norm:>7.1%}  {with_norm-no_norm:>+7.1%}")

    # Per-category breakdown for the worst transform
    worst_transform = min(
        ["case_swap", "space_insert", "synonym_sub"],
        key=lambda t: sum(transform_results[t].values())
    )
    clf_key = list(detectors.keys())[-1]
    tfn = TRANSFORMS[worst_transform]
    print(f"\n  scratch_classifier on '{worst_transform}' by category:")
    cats = sorted({r["category"] for r in attack})
    for cat in cats:
        cat_atk = [r for r in attack if r["category"] == cat]
        blocked = sum(detectors[clf_key].detect(tfn(r["text"])).blocked for r in cat_atk)
        print(f"    {cat:<26} {blocked}/{len(cat_atk)} ({blocked/len(cat_atk):.0%})")

    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
