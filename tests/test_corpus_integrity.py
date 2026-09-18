"""Structural integrity tests for corpus/injection_cases.yaml and its
relationship to docs/corpus-references.md.

Why these exist: the corpus is actively hand-edited across many sessions
(36 -> 72 -> 100 cases so far) with no schema enforcement anywhere else in
the codebase -- a typo'd category, a duplicate id, or a public_pattern case
that drifts out of sync with its citation doc would currently only be caught
by a human reading the YAML closely. These tests catch that mechanically,
the same "verify, don't assume" standard the rest of this project holds
itself to for detection numbers -- applied here to the corpus's own
structure instead."""
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
REFERENCES_PATH = REPO_ROOT / "docs" / "corpus-references.md"

VALID_CATEGORIES = {
    "direct_injection", "indirect_injection", "multi_turn_jailbreak",
    "encoding_obfuscation", "tool_scope_escalation",
}
VALID_EXPECTED_BEHAVIORS = {"block", "allow", "flag"}
VALID_ORIGINS = {"self_devised", "public_pattern"}
REQUIRED_FIELDS = {"id", "category", "origin", "vector", "payload", "expected_behavior"}


@pytest.fixture(scope="module")
def corpus():
    with open(CORPUS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_corpus_loads_and_is_nonempty(corpus):
    assert isinstance(corpus, list)
    assert len(corpus) > 0


def test_every_case_has_required_fields(corpus):
    missing = {c.get("id", "<no id>"): REQUIRED_FIELDS - set(c.keys()) for c in corpus}
    missing = {k: v for k, v in missing.items() if v}
    assert not missing, f"cases missing required fields: {missing}"


def test_case_ids_are_unique(corpus):
    ids = [c["id"] for c in corpus]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate case ids: {dupes}"


def test_case_ids_follow_gw_nnn_format_with_no_gaps(corpus):
    ids = sorted(c["id"] for c in corpus)
    pattern = re.compile(r"^GW-(\d{3})$")
    bad = [i for i in ids if not pattern.match(i)]
    assert not bad, f"case ids not matching GW-NNN format: {bad}"

    numbers = sorted(int(pattern.match(i).group(1)) for i in ids)
    expected = list(range(1, len(numbers) + 1))
    assert numbers == expected, (
        f"case numbering has gaps or doesn't start at 1 -- got {numbers[:5]}...{numbers[-5:]}, "
        f"expected a contiguous 1..{len(numbers)}"
    )


def test_category_values_are_from_the_known_set(corpus):
    bad = {c["id"]: c["category"] for c in corpus if c["category"] not in VALID_CATEGORIES}
    assert not bad, f"unknown category values: {bad}"


def test_expected_behavior_values_are_from_the_known_set(corpus):
    bad = {c["id"]: c["expected_behavior"] for c in corpus
           if c["expected_behavior"] not in VALID_EXPECTED_BEHAVIORS}
    assert not bad, f"unknown expected_behavior values: {bad}"


def test_origin_values_are_from_the_known_set(corpus):
    bad = {c["id"]: c["origin"] for c in corpus if c["origin"] not in VALID_ORIGINS}
    assert not bad, f"unknown origin values: {bad}"


def test_no_case_has_an_empty_payload(corpus):
    empty = [c["id"] for c in corpus if not c["payload"] or not c["payload"].strip()]
    assert not empty, f"cases with an empty/blank payload: {empty}"


def test_negative_controls_exist_in_every_category(corpus):
    """A category with zero expected_behavior=='allow' cases can't measure a
    false-positive rate at all for that category -- this exact gap (only 4
    negative controls total, none per-category) is what the 36->72 corpus
    expansion was built to close (docs/corpus_expansion_result.md). Guard
    against silently regressing back to that state as the corpus keeps growing."""
    by_category_allow = {}
    for c in corpus:
        if c["expected_behavior"] == "allow":
            by_category_allow.setdefault(c["category"], 0)
            by_category_allow[c["category"]] += 1
    missing = VALID_CATEGORIES - set(by_category_allow)
    assert not missing, (
        f"categories with zero negative controls (can't measure a false-positive "
        f"rate for them at all): {missing}"
    )


def test_every_public_pattern_case_has_a_real_world_citation():
    """docs/corpus-references.md exists specifically because a public_pattern
    label with no citation is just an unverified claim -- this test makes
    sure the doc doesn't silently fall behind the corpus as new
    public_pattern cases get added in later sessions."""
    if not REFERENCES_PATH.exists():
        pytest.skip("docs/corpus-references.md not present")

    with open(CORPUS_PATH, encoding="utf-8") as f:
        corpus = yaml.safe_load(f)
    references_text = REFERENCES_PATH.read_text(encoding="utf-8")

    public_pattern_ids = {c["id"] for c in corpus if c["origin"] == "public_pattern"}
    cited_ids = set(re.findall(r"\bGW-\d{3}\b", references_text))

    uncited = public_pattern_ids - cited_ids
    # Not a hard failure -- the corpus grows faster than citation research can
    # keep up, and docs/corpus-references.md says so explicitly. But silently
    # having MORE than a handful uncited defeats the doc's purpose, so this
    # is a soft ceiling, not a promise every single one is covered yet.
    assert len(uncited) <= 10, (
        f"{len(uncited)} public_pattern cases have no citation in "
        f"docs/corpus-references.md (more than the 10-case buffer this test "
        f"allows for): {sorted(uncited)}"
    )


def test_referenced_case_ids_actually_exist_and_are_public_pattern():
    """The inverse check: every GW-id docs/corpus-references.md cites should
    still exist in the corpus AND still be labeled public_pattern -- catches
    a case being deleted, renumbered, or re-labeled self_devised without the
    citation doc being updated to match."""
    if not REFERENCES_PATH.exists():
        pytest.skip("docs/corpus-references.md not present")

    with open(CORPUS_PATH, encoding="utf-8") as f:
        corpus = yaml.safe_load(f)
    by_id = {c["id"]: c for c in corpus}
    references_text = REFERENCES_PATH.read_text(encoding="utf-8")
    cited_ids = set(re.findall(r"\bGW-\d{3}\b", references_text))

    missing = [i for i in cited_ids if i not in by_id]
    assert not missing, f"docs/corpus-references.md cites ids no longer in the corpus: {missing}"

    wrong_origin = [i for i in cited_ids if i in by_id and by_id[i]["origin"] != "public_pattern"]
    assert not wrong_origin, (
        f"docs/corpus-references.md cites ids that are no longer origin=public_pattern: {wrong_origin}"
    )
