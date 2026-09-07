"""Fits the embedding-similarity detector's known-bad index from data/train.csv
(label==1 rows only -- we're indexing known attacks, not learning a decision
boundary, so benign examples aren't needed here) and saves it to models/."""
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector


def main():
    train_path = REPO_ROOT / "data" / "train.csv"
    known_bad_texts, known_bad_ids = [], []

    with open(train_path, encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if row["label"] == "1":
                known_bad_texts.append(row["text"])
                known_bad_ids.append(f"TRAIN-{i}")

    detector = EmbeddingSimilarityDetector()
    detector.fit(known_bad_texts, known_bad_ids)
    detector.save()

    print(f"Indexed {len(known_bad_texts)} known-bad examples into embedding_similarity detector.")
    print(f"Saved to {REPO_ROOT / 'models' / 'embedding_similarity'}")


if __name__ == "__main__":
    main()
