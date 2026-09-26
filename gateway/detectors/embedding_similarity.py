"""
Layer 2: Embedding-similarity prompt-injection detector.

SANDBOX-DRIVEN SUBSTITUTION, DOCUMENTED HONESTLY:
The build doc specifies transformer sentence embeddings (e.g. all-MiniLM-L6-v2).
This sandbox cannot download any pretrained model weights (see docs/decisions.md,
2026-09-05 entry) — huggingface.co and every alternate weight host checked are
unreachable. This layer therefore uses TF-IDF vectors (scikit-learn, fit locally,
no external download) + cosine similarity as a lighter-weight stand-in for
"embedding similarity." It is a real, working technique with a real limitation:
TF-IDF captures lexical overlap, not semantic meaning, so it generalizes to
*reworded* attacks less reliably than a transformer embedding would, and is
expected to still miss some paraphrase-heavy cases (see comparison table).
Swapping in sentence-transformers is a drop-in change to _vectorize() if this
ever runs somewhere with model-hub access.

No training loop: the vectorizer is *fit* once on the known-bad corpus (like
"indexing" reference embeddings), not trained on labeled data the way layer 3 is.
"""
import pickle  # nosec B403 - loads are integrity-checked (gateway/model_integrity.py)
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "embedding_similarity"
SIMILARITY_THRESHOLD = 0.35  # tuned empirically, see docs/decisions.md


@dataclass
class DetectionResult:
    blocked: bool
    layer: str
    confidence: float
    matched_pattern_id: str | None
    latency_ms: float
    details: dict = field(default_factory=dict)


class EmbeddingSimilarityDetector:
    def __init__(self):
        self.vectorizer: TfidfVectorizer | None = None
        # Pre-normalised (L2) rows so detect() reduces cosine similarity to a
        # single sparse dot product: no per-call cosine_similarity() overhead.
        self._known_bad_norm = None  # shape (N, vocab), L2-normalised rows
        self.known_bad_ids: list[str] = []

    def fit(self, known_bad_texts: list[str], known_bad_ids: list[str]):
        """'Indexes' the known-bad corpus. Called once at startup or after
        retraining -- analogous to embedding a red-team corpus and storing
        the vectors, per the build doc's layer-2 description."""
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            max_features=20000,
            sublinear_tf=True,
        )
        raw = self.vectorizer.fit_transform(known_bad_texts)
        self._known_bad_norm = normalize(raw, norm="l2")
        self.known_bad_ids = known_bad_ids

    def save(self, path: Path = MODEL_DIR):
        path.mkdir(parents=True, exist_ok=True)
        with open(path / "vectorizer.pkl", "wb") as f:
            pickle.dump(self.vectorizer, f)  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle - training-time write of our own artifact
        with open(path / "known_bad.pkl", "wb") as f:
            pickle.dump((self._known_bad_norm, self.known_bad_ids), f)  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle - training-time write of our own artifact

    def load(self, path: Path = MODEL_DIR):
        from gateway import model_integrity
        # pickle runs code chosen by the file's author: check the SHA-256 against models/MANIFEST.sha256 first (gateway/model_integrity.py)
        model_integrity.verify(path / "vectorizer.pkl")
        model_integrity.verify(path / "known_bad.pkl")
        with open(path / "vectorizer.pkl", "rb") as f:
            self.vectorizer = pickle.load(f)  # nosec B301 - integrity-checked above  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle - SHA-256 verified against models/MANIFEST.sha256
        with open(path / "known_bad.pkl", "rb") as f:
            stored, self.known_bad_ids = pickle.load(f)  # nosec B301 - integrity-checked above  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle - SHA-256 verified against models/MANIFEST.sha256
        # Re-normalise on load in case an older pickle stores the raw vectors.
        self._known_bad_norm = normalize(stored, norm="l2")

    def detect(self, text: str, threshold: float | None = None) -> DetectionResult:
        start = time.perf_counter()

        if self.vectorizer is None:
            raise RuntimeError("Detector not fitted/loaded. Call fit() or load() first.")

        effective_threshold = threshold if threshold is not None else SIMILARITY_THRESHOLD

        # Cosine similarity = dot(normalised_query, normalised_corpus.T)
        query_norm = normalize(self.vectorizer.transform([text]), norm="l2")
        similarities = (query_norm @ self._known_bad_norm.T).toarray()[0]

        best_idx = int(np.argmax(similarities))
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
                     "effective_threshold": effective_threshold},
        )
