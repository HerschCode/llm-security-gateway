"""Source hygiene guards found by the Phase 6 appsec scan (docs/security-scans.md).

1. No Python source file may contain invisible, format, combining or control characters as literals. Bandit B613 ("Trojan Source",
   CVE-2021-42574) flagged gateway/text_normalizer.py, whose zero-width-character regex was written with the characters themselves, so a
   reviewer could not see what it matched. Every such character is now a visible \\uXXXX escape.
2. The gateway must not import `random` for anything but non-security purposes (it does not import it at all): a PRNG is not a source of
   tokens or nonces. Nonces come from `secrets`.
"""
import ast
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ROOTS = ["gateway", "scripts", "tests", "project2_agent"]
SKIP_PARTS = {".venv", ".venv-pii", ".venv-sec", ".venv-garak", "__pycache__", "node_modules"}


def python_files():
    files = []
    for root in ROOTS:
        files += [p for p in (REPO / root).rglob("*.py") if not SKIP_PARTS & set(p.parts)]
    files += [p for p in (REPO / "redteam").glob("*.py")]
    return sorted(files)


def risky(c: str) -> bool:
    cat = unicodedata.category(c)
    return cat in ("Cf", "Mn", "Me", "Co", "Cn", "Zl", "Zp") or (cat == "Cc" and c not in "\t\n\r") or (cat == "Zs" and c != " ")


def test_there_are_python_files_to_check():
    assert len(python_files()) > 80


def test_no_python_source_contains_a_literal_invisible_or_control_character():
    offenders = []
    for p in python_files():
        text = p.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.split("\n"), 1):
            for c in line:
                if risky(c):
                    offenders.append(f"{p.relative_to(REPO)}:{lineno} U+{ord(c):04X} ({unicodedata.name(c, 'unnamed')})")
    assert not offenders, "write these as \\uXXXX escapes:\n" + "\n".join(offenders[:20])


def test_no_bidirectional_override_characters_anywhere_in_the_repository_text():
    bidi = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}
    hits = []
    for pattern in ("*.py", "*.md", "*.yml", "*.yaml", "*.toml", "*.txt"):
        for p in REPO.glob(pattern):
            hits += [str(p.name) for c in p.read_text(encoding="utf-8", errors="replace") if c in bidi]
        for root in ROOTS + ["docs", "config", ".github"]:
            for p in (REPO / root).rglob(pattern):
                if not SKIP_PARTS & set(p.parts):
                    hits += [str(p.relative_to(REPO)) for c in p.read_text(encoding="utf-8", errors="replace") if c in bidi]
    assert not hits, sorted(set(hits))


def test_the_gateway_package_does_not_use_the_random_module():
    """`random` is fine in seeded evaluation scripts; in gateway/ anything that needs unpredictability must use `secrets`."""
    offenders = []
    for p in (REPO / "gateway").rglob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name == "random" for a in node.names):
                offenders.append(str(p.relative_to(REPO)))
            if isinstance(node, ast.ImportFrom) and node.module == "random":
                offenders.append(str(p.relative_to(REPO)))
    assert not offenders, offenders
