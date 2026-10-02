"""
Layer 2, OPT-IN variant: real transformer sentence embeddings
(sentence-transformers/all-MiniLM-L6-v2) + cosine similarity -- the build doc's
ORIGINAL design for this layer, which gateway/detectors/embedding_similarity.py
substituted with TF-IDF back when this project's build environment had no
model-hub access (see docs/decisions.md, 2026-09-05).

That constraint no longer applies here (huggingface.co is reachable -- see the
2026-09-11 DistilBERT entries), so the substitution was tested for real rather
than left as an assumed-better hypothesis:
scripts/evaluate_sentence_transformer_similarity.py measured it against the
same corpus and known-bad index as TF-IDF. Result (docs/sentence_transformer_similarity_result.md):
**23% detection at 0% FP (best threshold 0.45), vs TF-IDF's 0%** -- a real,
non-leaked improvement (TF-IDF genuinely is dead weight in the ensemble; a
semantic embedding genuinely helps), but it comes at real cost: ~44ms/request
(vs TF-IDF's ~7ms) and, more importantly, sentence-transformers pulls in torch
-- the exact dependency 2026-09-11's classifier work removed from the serving
path specifically to fit Render's 512MB free tier.

**Decision: opt-in, not default.** Selected via EMBEDDING_BACKEND=sentence_transformer
(gateway/middleware.py); the free-tier deploy stays on TF-IDF (torch-free,
GATEWAY_LITE-independent), matching the same "don't force the heavier
dependency on everyone for a real but modest gain" reasoning already applied
to the LOO-CV embedding result and to GATEWAY_LITE's original purpose. Anyone
running the full local pipeline (docker compose, this repo's own dev
environment) can turn it on.
"""
import pickle  # nosec B403 - loads are integrity-checked (gateway/model_integrity.py)
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "embedding_similarity_st"
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# The threshold this project's own sweep found best (highest detection at 0%
# FP) -- see scripts/evaluate_sentence_transformer_similarity.py's output and
# docs/sentence_transformer_similarity_result.md. NOT the same number as
# TF-IDF's 0.35 -- cosine similarity scores from a different embedding space
# aren't comparable, using TF-IDF's threshold here would be a silent bug.
SIMILARITY_THRESHOLD = 0.45


@dataclass
class DetectionResult:
    blocked: bool
    layer: str
    confidence: float
    matched_pattern_id: str | None
    latency_ms: float
    details: dict = field(default_factory=dict)


class SentenceTransformerSimilarityDetector:
    """Same DetectionResult/detect() interface as
    gateway.detectors.embedding_similarity.EmbeddingSimilarityDetector --
    swappable in gateway/middleware.py, not a different contract."""

    def __init__(self):
        self.model = None
        self.known_bad_vectors: np.ndarray | None = None
        self.known_bad_ids: list[str] = []

    def _load_model(self):
        if self.model is None:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(MODEL_NAME)

    def fit(self, known_bad_texts: list[str], known_bad_ids: list[str]):
        self._load_model()
        self.known_bad_vectors = self.model.encode(
            known_bad_texts, batch_size=64, show_progress_bar=False,
            convert_to_numpy=True, normalize_embeddings=True,
        )
        self.known_bad_ids = known_bad_ids

    def save(self, path: Path = MODEL_DIR):
        path.mkdir(parents=True, exist_ok=True)
        np.save(path / "known_bad_vectors.npy", self.known_bad_vectors)
        with open(path / "known_bad_ids.pkl", "wb") as f:
            pickle.dump(self.known_bad_ids, f)  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle - training-time write of our own artifact

    def load(self, path: Path = MODEL_DIR):
        self._load_model()
        from gateway import model_integrity
        model_integrity.verify(path / "known_bad_vectors.npy")
        model_integrity.verify(path / "known_bad_ids.pkl")     # pickle: check before deserializing
        self.known_bad_vectors = np.load(path / "known_bad_vectors.npy", allow_pickle=False)
        with open(path / "known_bad_ids.pkl", "rb") as f:
            self.known_bad_ids = pickle.load(f)  # nosec B301 - integrity-checked above  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle - SHA-256 verified against models/MANIFEST.sha256

    def detect(self, text: str, threshold: float | None = None) -> DetectionResult:
        start = time.perf_counter()

        if self.model is None or self.known_bad_vectors is None:
            raise RuntimeError("Detector not fitted/loaded. Call fit() or load() first.")

        effective_threshold = threshold if threshold is not None else SIMILARITY_THRESHOLD

        query_vector = self.model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
        # Vectors are pre-normalized, so cosine similarity is just a dot product.
        similarities = self.known_bad_vectors @ query_vector[0]

        best_idx = int(similarities.argmax())
        best_score = float(similarities[best_idx])
        best_match_id = self.known_bad_ids[best_idx]

        blocked = best_score >= effective_threshold
        latency_ms = (time.perf_counter() - start) * 1000

        return DetectionResult(
            blocked=blocked,
            layer="embedding_similarity",
            confidence=best_score,
            matched_pattern_id=best_match_id if blocked else None,
            latency_ms=latency_ms,
            details={"nearest_known_bad_id": best_match_id, "similarity": best_score,
                     "effective_threshold": effective_threshold, "backend": "sentence_transformer"},
        )
