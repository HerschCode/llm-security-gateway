"""Print a SARIF file's results as a GitHub workflow annotation, so scanner findings can be read on the run page (and through the public check-runs API)
without downloading the artifact, which needs a login.

    python scripts/sarif_to_annotations.py semgrep.sarif --title Semgrep

One annotation carries every finding, one per line: level, rule id, file:line, the message (shortened). A file that is missing or has no results prints a
notice saying so instead of failing, so the step never hides the scanner's own exit status.
"""
import argparse
import json
import sys
from pathlib import Path

MAX_CHARS = 60_000          # GitHub truncates a longer annotation message
MAX_MESSAGE = 220


def findings(sarif: dict) -> list[str]:
    out = []
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "?")
            line = loc.get("region", {}).get("startLine", 0)
            msg = " ".join(str(r.get("message", {}).get("text", "")).split())[:MAX_MESSAGE]
            level = r.get("level", "warning")
            if r.get("suppressions"):                     # a `nosemgrep` comment: reported by the tool, but not a failure
                level = f"suppressed({level})"
            out.append(f"{level} {r.get('ruleId', '?')} {uri}:{line} {msg}")
    return out


def escape(text: str, *, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def annotation(title: str, lines: list[str]) -> str:
    return f"::notice title={escape(f'{title}: {len(lines)} findings', prop=True)}::{escape(chr(10).join(lines)[:MAX_CHARS])}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif")
    ap.add_argument("--title", default="SARIF")
    ap.add_argument("--log", help="the scanner's own console output; its last lines are printed as a second annotation")
    args = ap.parse_args(argv)
    path = Path(args.sarif)
    if not path.exists():
        print(f"::notice title={escape(args.title, prop=True)}::no SARIF file at {escape(str(path))}")
        return 0
    lines = findings(json.loads(path.read_text(encoding="utf-8")))
    print(annotation(args.title, lines))
    sys.stdout.write("\n".join(lines) + "\n")
    if args.log and Path(args.log).exists():
        tail = Path(args.log).read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
        print(f"::notice title={escape(args.title + ' console output', prop=True)}::{escape(chr(10).join(tail)[-MAX_CHARS:])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
