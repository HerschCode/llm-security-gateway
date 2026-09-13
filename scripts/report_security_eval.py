"""
Parse docs/comparison_table.md and write reports/p3_security_eval.json.

Offline -- no torch or API keys needed. The table is committed and updated
every time scripts/evaluate.py runs against the 120-case corpus.

To re-run the full evaluation (updates comparison_table.md):
  python scripts/evaluate.py  (requires full requirements.txt with torch)
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


def main():
    table_path = REPO_ROOT / "docs" / "comparison_table.md"
    if not table_path.exists():
        print("comparison_table.md not found. Run: python scripts/evaluate.py  (requires full requirements.txt)")
        sys.exit(1)

    layers = []
    for line in table_path.read_text().splitlines():
        if not line.startswith("|") or "Layer" in line or "---" in line:
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) >= 4 and parts[0]:
            layers.append({
                "layer": parts[0],
                "detection": _parse_rate(parts[1]),
                "false_positive": _parse_rate(parts[2]),
                "latency_ms": _parse_latency(parts[3]),
            })

    corpus_size = layers[0]["detection"]["denominator"] if layers else None
    benign_controls = layers[0]["false_positive"]["denominator"] if layers else None

    report = {
        "corpus_size": corpus_size,
        "benign_controls": benign_controls,
        "layers": layers,
        "source": "docs/comparison_table.md",
    }

    out = REPO_ROOT / "reports" / "p3_security_eval.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSaved → {out}")


if __name__ == "__main__":
    main()
