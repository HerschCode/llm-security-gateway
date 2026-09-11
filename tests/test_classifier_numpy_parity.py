"""Verifies the torch-free numpy classifier (gateway/detectors/classifier_numpy.py)
produces the same decisions -- and near-identical probabilities -- as the
original torch model (gateway/detectors/classifier.py) it was exported from.
Removing torch from the serving path is only safe to ship if this holds; don't
assume parity, check it, the same discipline the rest of this project applies
to every other claimed-equivalent substitution."""
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def _corpus_texts():
    with open(REPO_ROOT / "corpus" / "injection_cases.yaml", encoding="utf-8") as f:
        cases = yaml.safe_load(f)
    return [c["payload"] for c in cases]


@pytest.fixture(scope="module")
def both_detectors():
    if not (REPO_ROOT / "models" / "scratch_classifier" / "weights.npz").exists():
        pytest.skip("weights.npz not exported -- run scripts/export_classifier_to_numpy.py first.")
    from gateway.detectors.classifier import ScratchClassifierDetector
    from gateway.detectors.classifier_numpy import ScratchClassifierDetectorNumpy

    torch_det = ScratchClassifierDetector()
    torch_det.load()
    numpy_det = ScratchClassifierDetectorNumpy()
    numpy_det.load()
    return torch_det, numpy_det


def test_numpy_classifier_matches_torch_on_full_corpus(both_detectors):
    torch_det, numpy_det = both_detectors
    max_prob_diff = 0.0
    for text in _corpus_texts():
        t = torch_det.detect(text)
        n = numpy_det.detect(text)
        assert t.blocked == n.blocked, f"decision mismatch on: {text[:60]!r}"
        max_prob_diff = max(max_prob_diff, abs(t.confidence - n.confidence))
    # float32 (torch) vs float64-accumulated (numpy) rounding -- expect near-zero,
    # not bitwise-identical.
    assert max_prob_diff < 1e-4, f"probabilities diverged by {max_prob_diff}"


def test_numpy_classifier_matches_torch_on_benign_indomain_queries(both_detectors):
    torch_det, numpy_det = both_detectors
    path = REPO_ROOT / "corpus" / "benign_indomain_queries.yaml"
    if not path.exists():
        pytest.skip("benign_indomain_queries.yaml not present")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    queries = data.get("eval", data) if isinstance(data, dict) else data
    texts = [q["text"] if isinstance(q, dict) else q for q in queries][:15]
    for text in texts:
        t = torch_det.detect(text)
        n = numpy_det.detect(text)
        assert t.blocked == n.blocked, f"decision mismatch on: {text[:60]!r}"
