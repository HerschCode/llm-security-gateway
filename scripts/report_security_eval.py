"""
Parse docs/comparison_table.md + reports/p3_external_benchmark.json and write
reports/p3_security_eval.json.

Offline -- no torch or API keys needed. The table is committed and updated
every time scripts/evaluate.py runs against the 120-case corpus. The external
benchmark JSON is committed after running scripts/external_benchmark.py.

To re-run the full evaluation (updates comparison_table.md):
  python scripts/evaluate.py  (requires full requirements.txt with torch)

To re-run the external benchmark:
  python scripts/external_benchmark.py  (requires full requirements.txt with torch)
"""
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _parse_rate(cell):
    m = re.search(r"(\d+)%\s*\((\d+)/(\d+)\)", cell)
    if m:
        return {"pct": int(m.group(1)), "numerator": int(m.group(2)), "denominator": int(m.group(3))}
    return None


def _parse_latency(cell):
    m = re.search(r"([\d.]+)", cell.strip())
    return float(m.group(1)) if m else None


def _parse_per_category(table_text: str) -> dict:
    """Extract per-category rows from the comparison table."""
    in_section = False
    per_cat = {}
    for line in table_text.splitlines():
        if "Per-category detection rates" in line:
            in_section = True
            continue
        if in_section and line.startswith("##"):
            break
        if in_section and line.startswith("|") and "Category" not in line and "---" not in line:
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) < 4:
                continue
            cat_cell = parts[0]
            m = re.match(r"(.+?)\s*\((\d+)\)", cat_cell)
            if not m:
                continue
            cat_name = m.group(1).strip()
            per_cat[cat_name] = {
                "n_attacks": int(m.group(2)),
                "rule_based": _parse_rate(parts[1]),
                "embedding_similarity": _parse_rate(parts[2]),
                "scratch_classifier": _parse_rate(parts[3]),
            }
    return per_cat


def main():
    table_path = REPO_ROOT / "docs" / "comparison_table.md"
    if not table_path.exists():
        print("comparison_table.md not found. Run: python scripts/evaluate.py  (requires full requirements.txt)")
        sys.exit(1)

    table_text = table_path.read_text()
    layers = []
    for line in table_text.splitlines():
        if not line.startswith("|") or "Layer" in line or "---" in line or "Category" in line:
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) >= 4 and parts[0] and "%" in parts[1]:
            try:
                layers.append({
                    "layer": parts[0],
                    "detection": _parse_rate(parts[1]),
                    "false_positive": _parse_rate(parts[2]),
                    "latency_ms": _parse_latency(parts[3]),
                })
            except (ValueError, IndexError, KeyError, TypeError):      # a malformed table row is skipped, not fatal
                continue

    corpus_size = layers[0]["detection"]["denominator"] if layers else None
    benign_controls = layers[0]["false_positive"]["denominator"] if layers else None
    per_cat = _parse_per_category(table_text)

    # Load external benchmark if available
    ext_path = REPO_ROOT / "reports" / "p3_external_benchmark.json"
    external_benchmark = None
    if ext_path.exists():
        external_benchmark = json.loads(ext_path.read_text())

    report = {
        "corpus_size": corpus_size,
        "benign_controls": benign_controls,
        "layers": layers,
        "per_category": per_cat,
        "external_benchmark": external_benchmark,
        "source": "docs/comparison_table.md",
        "interpretation": (
            "Internal corpus (data/eval.csv) is deliberately adversarial — 5 attack categories "
            "including encoding_obfuscation and tool_scope_escalation that evade classic detectors. "
            "The external benchmark (jailbreak_llms, Shen et al. 2023) shows higher detection rates "
            "because published jailbreaks skew toward direct/role-play patterns. "
            "The gap between internal and external rates quantifies corpus difficulty, not overfitting."
        ),
    }

    out = REPO_ROOT / "reports" / "p3_security_eval.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSaved → {out}")


if __name__ == "__main__":
    main()
