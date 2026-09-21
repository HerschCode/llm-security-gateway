"""Layer 3 inference wrapper -- same DetectionResult interface as layers 1 and 2,
so the gateway can call all three detectors polymorphically."""
import time
from dataclasses import dataclass, field

import torch

from gateway.detectors.scratch_classifier_model import encode, load_artifacts

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


class ScratchClassifierDetector:
    def __init__(self):
        self.model = None
        self.vocab = None

    def load(self):
        self.model, self.vocab = load_artifacts()

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
        input_tensor = torch.tensor([ids], dtype=torch.long)
        with torch.no_grad():
            logit = self.model(input_tensor)
            probability = torch.sigmoid(logit).item()

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
