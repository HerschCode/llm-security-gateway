"""
Knowledge distillation: train a smaller "student" model to replicate the
ensemble's BLOCK/FLAG/ALLOW decisions without running all three layers at
inference time.

The teacher here is the full detection ensemble (rule_based + embedding + MLP
classifier). The student is a single lightweight text classifier that learns from
the teacher's probability outputs (soft targets) rather than the binary ground-truth
labels — this is the core soft-label distillation idea from Hinton et al. 2015.

Why distillation instead of just retraining?
  - The ensemble's combined decisions are more informative than the original YAML
    labels, especially on edge cases where one layer fires and another does not.
  - A single-model student eliminates the latency of three sequential checks at
    inference time while retaining most of the ensemble's discrimination.
  - This is a named gap in the README ("knowledge distillation") — this script
    closes it as a proof-of-concept; it is not yet wired into the gateway's live
    inference path.

Usage (from repo root):
  python scripts/distill_to_student.py [--corpus corpus/injection_cases.yaml] [--output models/student.pkl]

Required packages (already in requirements.txt):
  scikit-learn, numpy, pyyaml, sentence-transformers
"""

import argparse
import pickle
from pathlib import Path

import numpy as np
import yaml
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sentence_transformers import SentenceTransformer


# ── Teacher: the production ensemble ─────────────────────────────────────────

def _load_teacher():
    """Return the gateway's real DetectionEnsemble (teacher)."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from src.detection.ensemble import DetectionEnsemble
    return DetectionEnsemble()


def _teacher_predict(ensemble, texts: list[str]) -> np.ndarray:
    """Run the teacher on each text; return (N, 3) soft probabilities.

    The ensemble returns a DetectionResult with a string action (BLOCK/FLAG/ALLOW)
    and a float score. We map that to a 3-class soft-label vector:
      BLOCK  → [1.0, 0.0, 0.0]
      FLAG   → [0.0, 1.0, 0.0]
      ALLOW  → [0.0, 0.0, 1.0]

    A real distillation run would use the raw probability outputs from each
    sub-model, not a one-hot encoding of the final decision. This skeleton uses
    the binary decision as a stand-in so it runs without modifying the ensemble
    API — replace _soft_label() with real probability extraction when ready.
    """
    action_to_index = {"BLOCK": 0, "FLAG": 1, "ALLOW": 2}
    probs = np.zeros((len(texts), 3), dtype=float)
    for i, text in enumerate(texts):
        result = ensemble.check(text)
        idx = action_to_index.get(result.action, 2)
        probs[i, idx] = 1.0
    return probs


# ── Student: a lightweight logistic classifier over embeddings ────────────────

def _embed(model: SentenceTransformer, texts: list[str]) -> np.ndarray:
    return model.encode(texts, show_progress_bar=True, convert_to_numpy=True)


def _train_student(X: np.ndarray, soft_labels: np.ndarray) -> LogisticRegression:
    """Fit a logistic regression on soft teacher labels.

    The student minimises cross-entropy against the teacher's soft probability
    vectors rather than the hard ground-truth labels. With one-hot soft labels
    (produced by _teacher_predict above) this degenerates to standard supervised
    training — replace with actual probabilities for real temperature-scaled
    distillation (Hinton et al., T=4 is a common starting point).
    """
    hard_labels = np.argmax(soft_labels, axis=1)
    clf = LogisticRegression(
        max_iter=1000,
        C=1.0,
        multi_class="multinomial",
        solver="lbfgs",
        random_state=42,
    )
    clf.fit(X, hard_labels)
    return clf


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Distil detection ensemble into a student model")
    parser.add_argument("--corpus", default="corpus/injection_cases.yaml")
    parser.add_argument("--output", default="models/student.pkl")
    parser.add_argument("--embed-model", default="all-MiniLM-L6-v2",
                        help="sentence-transformers model for student features")
    args = parser.parse_args()

    print(f"Loading corpus from {args.corpus}")
    with open(args.corpus) as f:
        cases = yaml.safe_load(f)["cases"]
    texts = [c["text"] for c in cases]
    print(f"  {len(texts)} cases loaded")

    print("Loading teacher (detection ensemble)…")
    teacher = _load_teacher()

    print("Generating soft labels from teacher…")
    soft_labels = _teacher_predict(teacher, texts)
    label_dist = {k: int(v) for k, v in zip(["BLOCK", "FLAG", "ALLOW"], soft_labels.sum(axis=0).astype(int))}
    print(f"  Teacher label distribution: {label_dist}")

    print(f"Embedding texts with {args.embed_model}…")
    embedder = SentenceTransformer(args.embed_model)
    X = _embed(embedder, texts)
    print(f"  Embedding shape: {X.shape}")

    print("Training student (logistic regression on soft labels)…")
    student = _train_student(X, soft_labels)

    hard_labels = np.argmax(soft_labels, axis=1)
    train_acc = (student.predict(X) == hard_labels).mean()
    print(f"  Student train accuracy vs. teacher labels: {train_acc:.3f}")
    print("  (Train accuracy is a sanity check, not a quality metric — use the")
    print("   held-out corpus/injection_cases.yaml corpus for real evaluation.)")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump({"student": student, "embedder_name": args.embed_model}, f)
    print(f"Student saved to {output_path}")

    print("\nNext steps:")
    print("  1. Replace one-hot soft labels with real ensemble probability scores")
    print("     (per-layer sigmoid outputs, temperature-scaled at T=4)")
    print("  2. Evaluate on a held-out split: scripts/evaluate.py --model-path", args.output)
    print("  3. Compare student latency against ensemble (scripts/measure_latency.py)")
    print("  4. Wire into gateway/middleware if latency wins and F1 stays within 2pp")


if __name__ == "__main__":
    main()
