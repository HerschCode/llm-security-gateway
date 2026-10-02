"""The README's results tables are generated from the committed result files, so they cannot say something the data does not.

If this fails after you changed a result file (or the wording rules in scripts/render_readme_headline.py), regenerate the block:

    python -m scripts.render_readme_headline --write
"""
from pathlib import Path

from scripts.render_readme_headline import END, START, current_block, render

REPO = Path(__file__).resolve().parents[1]
README = (REPO / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def test_readme_has_exactly_one_generated_block():
    assert README.count(START) == 1 and README.count(END) == 1


def test_readme_headline_block_matches_the_result_files():
    assert current_block(README) == render()


def test_the_generated_block_states_its_caveats():
    block = render()
    for must_say in ("never container-tested", "Same-author test design", "author-written", "Synthetic data"):
        assert must_say in block, f"the headline block lost a caveat: {must_say!r}"


def test_a_partial_adaptive_run_is_labelled_partial():
    """A run that stopped when the free-tier quota ran out must not read like a complete run."""
    import json
    for f in (REPO / "reports" / "redteam").glob("adaptive-*.json"):
        d = json.loads(f.read_text(encoding="utf-8"))
        if len(d["results"]) < 6:
            assert f"{len(d['results'])} of 6 goals" in render()
