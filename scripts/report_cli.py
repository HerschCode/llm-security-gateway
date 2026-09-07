"""
Tier 2: "a small dashboard or CLI report view for the attack-simulation
results." A terminal report, not a web dashboard -- reads the artifacts
already produced by scripts/evaluate.py and scripts/run_redteam.py (the
corpus's own status_by_layer fields, plus the redteam markdown reports) and
renders a human-scannable summary. Stdlib only, no extra dependency for
something this small.

Usage:
  python scripts/report_cli.py
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
REDTEAM_DIRECT = REPO_ROOT / "docs" / "redteam_report_direct_stub_ops_agent.md"
REDTEAM_GATEWAY = REPO_ROOT / "docs" / "redteam_report_gateway_stub_ops_agent.md"

WIDTH = 78


def _rule(char="-"):
    print(char * WIDTH)


def _header(title):
    _rule("=")
    print(title.center(WIDTH))
    _rule("=")


def report_detection_layers():
    if not CORPUS_PATH.exists():
        print("No corpus found.")
        return

    with open(CORPUS_PATH, encoding="utf-8") as f:
        cases = yaml.safe_load(f)

    if not any(c.get("status_by_layer") for c in cases):
        print("No evaluation results yet -- run scripts/evaluate.py first.")
        return

    _header("DETECTION LAYER RESULTS (by category)")

    layers = ["rule_based", "embedding_similarity", "scratch_classifier"]
    by_category = defaultdict(list)
    for c in cases:
        by_category[c["category"]].append(c)

    for category, category_cases in sorted(by_category.items()):
        print(f"\n{category} ({len(category_cases)} cases)")
        for layer in layers:
            passed = sum(
                1 for c in category_cases
                if c.get("status_by_layer", {}).get(layer) == "pass"
            )
            total = sum(1 for c in category_cases if layer in c.get("status_by_layer", {}))
            if total == 0:
                continue
            bar_len = 20
            filled = int(bar_len * passed / total) if total else 0
            bar = "#" * filled + "." * (bar_len - filled)
            print(f"  {layer:<22} [{bar}] {passed}/{total}")

    _rule()
    print("Legend: bar shows pass rate (status_by_layer == 'pass') per category, per layer.")


def _parse_redteam_summary(path: Path):
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    title_match = re.search(r"^# (.+)$", text, re.MULTILINE)
    score_match = re.search(r"(\d+)/(\d+) cases passed", text)
    fail_rows = re.findall(r"\| (GW-\d+) \| (\w+) \| \w+ \| \w+ \| [^|]* \| [\d.]+ \| FAIL \|", text)
    return {
        "title": title_match.group(1) if title_match else path.stem,
        "passed": int(score_match.group(1)) if score_match else None,
        "total": int(score_match.group(2)) if score_match else None,
        "failures": fail_rows,
    }


def report_redteam_comparison():
    direct = _parse_redteam_summary(REDTEAM_DIRECT)
    gateway = _parse_redteam_summary(REDTEAM_GATEWAY)

    if not direct and not gateway:
        print("\nNo attack-simulation reports found -- run scripts/run_redteam.py first "
              "(both --bypass-gateway and through a live gateway) to populate this.")
        return

    _header("ATTACK SIMULATION: GATEWAY ON vs. OFF")
    print()
    if direct:
        pct = direct["passed"] / direct["total"] * 100 if direct["total"] else 0
        print(f"  WITHOUT gateway (direct to backend):  {direct['passed']}/{direct['total']} ({pct:.0f}%)")
    if gateway:
        pct = gateway["passed"] / gateway["total"] * 100 if gateway["total"] else 0
        print(f"  WITH gateway in front:                 {gateway['passed']}/{gateway['total']} ({pct:.0f}%)")

    if direct and gateway:
        delta = gateway["passed"] - direct["passed"]
        print(f"\n  Delta: gateway fixed {delta} additional case(s) out of {gateway['total']}.")

    if gateway and gateway["failures"]:
        print(f"\n  Still failing WITH the gateway on ({len(gateway['failures'])}):")
        for case_id, category in gateway["failures"]:
            print(f"    - {case_id} ({category})")
    elif gateway:
        print("\n  No failures with the gateway on.")


def main():
    report_detection_layers()
    print()
    report_redteam_comparison()
    print()


if __name__ == "__main__":
    main()
