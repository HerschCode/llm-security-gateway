"""
Layer 3 inference, torch-free.

The trained model (gateway/detectors/scratch_classifier_model.py) is tiny --
an 8000x64 embedding table, mean-pool, and a 64->32->1 MLP head -- small enough
that its forward pass is a handful of numpy operations. There was never a real
reason SERVING it needed the ~700MB torch runtime; torch is only genuinely
needed for TRAINING (autograd, the optimizer, the DataLoader). This module
re-implements exactly ScratchClassifier.forward() (see that file) using the
weights exported by scripts/export_classifier_to_numpy.py into
models/scratch_classifier/weights.npz.

Why it matters: removing torch from the runtime import graph is what lets the
FULL 3-layer ensemble (not just lite mode) fit Render's 512MB free tier -- see
docs/decisions.md. gateway/middleware.py now loads this by default; the old
torch-backed gateway/detectors/classifier.py is kept only for
scripts/evaluate.py-style offline comparison and tests that want to assert
parity, not for the serving path.

Correctness isn't assumed -- tests/test_classifier_numpy_parity.py runs both
the torch model and this module over the full corpus and asserts identical
block/allow decisions and near-identical probabilities (float32 vs numpy
float64 accumulation can differ in the last few decimal places).
"""
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from gateway.detectors.text_encoding import encode, PAD_IDX

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "scratch_classifier"
CLASSIFIER_THRESHOLD = 0.5


# Inputs shorter than this many word tokens are not classified. The classifier mean-pools token
# embeddings, so a 1-2 word message is dominated by one embedding and scores erratically
# ("ok" scored 1.0, "hello" 0.4-0.8 across trained versions). Measured on held-out data
# (docs/retraining-flow.md): removes almost all short-message false positives while only ~2 of
# ~1,250 held-out attacks are this short; the rule-based layer still inspects every input.
CLASSIFIER_MIN_TOKENS = 3


def _too_short(text: str) -> bool:
    import re
    return len(re.findall(r"\w+", text)) < CLASSIFIER_MIN_TOKENS


@dataclass
class DetectionResult:
    blocked: bool
    layer: str
    confidence: float
    matched_pattern_id: str | None
    latency_ms: float
    details: dict = field(default_factory=dict)


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


class NumpyScratchClassifier:
    """Holds the exported weights and runs the forward pass with plain numpy.
    Mirrors ScratchClassifier.forward() in scratch_classifier_model.py term for
    term -- see that file for the architecture this must stay in sync with."""

    def __init__(self, weights: dict):
        self.embedding = weights["embedding.weight"]      # (vocab_size, embed_dim)
        self.fc1_w = weights["fc1.weight"]                 # (hidden_dim, embed_dim) -- nn.Linear stores (out, in)
        self.fc1_b = weights["fc1.bias"]                   # (hidden_dim,)
        self.fc2_w = weights["fc2.weight"]                 # (1, hidden_dim)
        self.fc2_b = weights["fc2.bias"]                   # (1,)

    def forward_logit(self, ids: list[int]) -> float:
        ids_arr = np.asarray(ids, dtype=np.int64)
        embedded = self.embedding[ids_arr]                       # (seq_len, embed_dim)
        mask = (ids_arr != PAD_IDX).astype(np.float64)[:, None]  # (seq_len, 1)
        summed = (embedded.astype(np.float64) * mask).sum(axis=0)
        length = max(mask.sum(), 1.0)
        pooled = summed / length                                  # (embed_dim,)

        hidden = pooled @ self.fc1_w.T.astype(np.float64) + self.fc1_b.astype(np.float64)
        hidden = np.maximum(hidden, 0.0)                          # ReLU
        # dropout is a training-only regularizer -- eval mode is a no-op, same
        # as PyTorch's model.eval() (see load_artifacts() in the torch module).
        logit = hidden @ self.fc2_w.T.astype(np.float64) + self.fc2_b.astype(np.float64)
        return float(logit[0])


def load_numpy_artifacts(path: Path = MODEL_DIR) -> tuple[NumpyScratchClassifier, dict]:
    import json

    from gateway import model_integrity
    model_integrity.verify(path / "vocab.json")
    model_integrity.verify(path / "weights.npz")
    with open(path / "vocab.json", encoding="utf-8") as f:
        vocab = json.load(f)
    npz = np.load(path / "weights.npz", allow_pickle=False)
    model = NumpyScratchClassifier({k: npz[k] for k in npz.files})
    return model, vocab


class ScratchClassifierDetectorNumpy:
    """Same interface as gateway.detectors.classifier.ScratchClassifierDetector
    (drop-in replacement), no torch import anywhere in this module or its
    dependency chain."""

    def __init__(self):
        self.model = None
        self.vocab = None

    def load(self):
        self.model, self.vocab = load_numpy_artifacts()

    def detect(self, text: str, threshold: float | None = None) -> DetectionResult:
        start = time.perf_counter()

        if self.model is None:
            raise RuntimeError("Detector not loaded. Call load() first.")

        if _too_short(text):
            return DetectionResult(blocked=False, layer="scratch_classifier", confidence=0.0,
                                   matched_pattern_id=None, latency_ms=(time.perf_counter() - start) * 1000,
                                   details={"skipped": "input shorter than CLASSIFIER_MIN_TOKENS"})

        effective_threshold = threshold if threshold is not None else CLASSIFIER_THRESHOLD

        ids = encode(text, self.vocab)
        logit = self.model.forward_logit(ids)
        probability = float(_sigmoid(np.array(logit)))

        blocked = probability >= effective_threshold
        latency_ms = (time.perf_counter() - start) * 1000

        return DetectionResult(
            blocked=blocked,
            layer="scratch_classifier",
            confidence=probability,
            matched_pattern_id="SC-CLASSIFIER" if blocked else None,
            latency_ms=latency_ms,
            details={"probability": probability, "effective_threshold": effective_threshold},
        )
