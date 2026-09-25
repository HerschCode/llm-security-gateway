"""Relative links and heading anchors in the documentation must resolve.

The README was split in Phase 7 and its old sections moved into docs/; a moved section is exactly what breaks links silently. External URLs are not fetched
(that would make the suite depend on the network); only links to files in this repository and to headings inside them are checked.
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# The documents a reader is sent to from the README, plus everything under docs/. Older reports keep whatever links they were written with.
DOCUMENTS = sorted(
    [REPO / n for n in ("README.md", "SECURITY.md", "DEPLOY.md", "HIGHLIGHTS.md")]
    + list((REPO / "docs").glob("*.md"))
    + [REPO / "reports" / "redteam-2026-09.md"]
)

_FENCE = re.compile(r"^\s*(```|~~~)")
_LINK = re.compile(r"!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def _lines_outside_code(text: str):
    fenced = False
    for line in text.splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield re.sub(r"`[^`\n]*`", "", line)        # inline code is not a link


def slug(heading: str) -> str:
    """GitHub's heading anchor: strip markup, lowercase, drop punctuation, spaces become hyphens."""
    h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    h = re.sub(r"[`*]", "", h).lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out = set()
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        m = None if fenced else _HEADING.match(line)
        if m:
            base = slug(m.group(2))
            n = seen.get(base, 0)
            seen[base] = n + 1
            out.add(base if n == 0 else f"{base}-{n}")
    return out


def broken_links(path: Path) -> list[str]:
    problems = []
    text = path.read_text(encoding="utf-8")
    for line in _lines_outside_code(text):
        for target in _LINK.findall(line):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            file_part, _, anchor = target.partition("#")
            dest = path if not file_part else (path.parent / file_part).resolve()
            if not dest.exists():
                problems.append(f"{path.relative_to(REPO)}: {target}: no such file")
            elif anchor and dest.suffix == ".md" and anchor not in anchors(dest):
                problems.append(f"{path.relative_to(REPO)}: {target}: no heading with that anchor in {dest.relative_to(REPO)}")
    return problems


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: str(p.relative_to(REPO)))
def test_links_resolve(path):
    assert not broken_links(path)


def test_slug_matches_github():
    assert slug("Known limitations (stated plainly, not buried)") == "known-limitations-stated-plainly-not-buried"
    assert slug("What's real vs. substituted") == "whats-real-vs-substituted"
    assert slug("Guard-model baseline: `ProtectAI` & friends") == "guard-model-baseline-protectai--friends"


def test_repeated_headings_get_numbered_anchors(tmp_path):
    f = tmp_path / "a.md"
    f.write_text("# Same\n\n## Same\n\n```\n# not a heading\n```\n", encoding="utf-8")
    assert anchors(f) == {"same", "same-1"}


def test_checker_finds_a_broken_link(tmp_path, monkeypatch):
    (tmp_path / "there.md").write_text("# Here\n", encoding="utf-8")
    doc = tmp_path / "doc.md"
    doc.write_text("[ok](there.md#here) [bad file](nope.md) [bad anchor](there.md#missing) [web](https://example.com/x) `[in code](nope.md)`\n", encoding="utf-8")
    monkeypatch.setitem(globals(), "REPO", tmp_path)          # report paths relative to the temporary tree
    found = broken_links(doc)
    assert len(found) == 2 and any("nope.md" in f for f in found) and any("#missing" in f for f in found)
