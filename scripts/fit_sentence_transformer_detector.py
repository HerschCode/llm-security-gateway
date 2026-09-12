"""Fits the OPT-IN sentence-transformer layer-2 detector
(gateway/detectors/embedding_similarity_st.py) from the same known-bad set as
the default TF-IDF layer (data/train.csv, label==1) -- same index contents, a
different embedding of it, so the comparison in
docs/sentence_transformer_similarity_result.md is apples-to-apples.

Requires: pip install sentence-transformers (or `pip install ".[semantic]"`).
Not needed for the default TF-IDF/free-tier deploy."""
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors.embedding_similarity_st import SentenceTransformerSimilarityDetector


def main():
    train_path = REPO_ROOT / "data" / "train.csv"
    known_bad_texts, known_bad_ids = [], []

    with open(train_path, encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if row["label"] == "1":
                known_bad_texts.append(row["text"])
                known_bad_ids.append(f"TRAIN-{i}")

    detector = SentenceTransformerSimilarityDetector()
    detector.fit(known_bad_texts, known_bad_ids)
    detector.save()

    print(f"Indexed {len(known_bad_texts)} known-bad examples into the "
          f"sentence-transformer embedding_similarity detector.")
    print(f"Saved to {REPO_ROOT / 'models' / 'embedding_similarity_st'}")


if __name__ == "__main__":
    main()
