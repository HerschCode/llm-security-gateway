"""
Layer 3: "Fine-tuned classifier" layer -- IMPORTANT NAMING NOTE.

The build doc specifies fine-tuning a pretrained DistilBERT-scale model. This
sandbox cannot download any pretrained weights (see docs/decisions.md). What's
built here instead is a small classifier TRAINED FROM SCRATCH: an embedding
matrix with randomly-initialized vectors (no pretrained knowledge baked in),
mean-pooled over the input tokens, feeding a 2-layer MLP classification head.
It has a real training loop (train/val split, BCE loss, early stopping) and
produces a genuine precision/recall story on held-out data -- it teaches the
same "transferable ML skill" the build doc wants from this layer. It is NOT a
fine-tune. A separate script (scripts/train_distilbert_finetune.py) contains
the actual DistilBERT fine-tuning code, written to run in an environment with
model-hub access, with results explicitly marked not-yet-run.
"""
import json
from pathlib import Path

import torch
import torch.nn as nn

# Tokenizer/vocab/encode + the size constants live in text_encoding.py, which
# has no torch import -- re-exported here for backward compatibility (training
# scripts import them from this module) without dragging torch into anything
# that only needs encode()/PAD_IDX (see gateway/detectors/classifier_numpy.py).
from gateway.detectors.text_encoding import (  # noqa: F401
    tokenize, build_vocab, encode,
    MAX_VOCAB_SIZE, MAX_SEQ_LEN, EMBED_DIM, HIDDEN_DIM, PAD_IDX, UNK_IDX,
)

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "scratch_classifier"


class ScratchClassifier(nn.Module):
    """Embedding (trained from scratch, no pretrained init) -> mean pool -> MLP head."""

    def __init__(self, vocab_size: int, embed_dim: int = EMBED_DIM, hidden_dim: int = HIDDEN_DIM):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)
        self.fc1 = nn.Linear(embed_dim, hidden_dim)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.2)
        self.fc2 = nn.Linear(hidden_dim, 1)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        # input_ids: (batch, seq_len)
        embedded = self.embedding(input_ids)                     # (batch, seq_len, embed_dim)
        mask = (input_ids != PAD_IDX).unsqueeze(-1).float()       # (batch, seq_len, 1)
        summed = (embedded * mask).sum(dim=1)                     # (batch, embed_dim)
        lengths = mask.sum(dim=1).clamp(min=1)                    # (batch, 1)
        pooled = summed / lengths                                 # mean pool, ignoring padding
        hidden = self.relu(self.fc1(pooled))
        hidden = self.dropout(hidden)
        logit = self.fc2(hidden)                                  # (batch, 1)
        return logit.squeeze(-1)


def save_artifacts(model: ScratchClassifier, vocab: dict, path: Path = MODEL_DIR):
    path.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), path / "model.pt")
    with open(path / "vocab.json", "w", encoding="utf-8") as f:
        json.dump(vocab, f)


def load_artifacts(path: Path = MODEL_DIR) -> tuple[ScratchClassifier, dict]:
    with open(path / "vocab.json", encoding="utf-8") as f:
        vocab = json.load(f)
    model = ScratchClassifier(vocab_size=len(vocab))
    model.load_state_dict(torch.load(path / "model.pt", map_location="cpu", weights_only=True))
    model.eval()
    return model, vocab
