"""Trains the from-scratch classifier (gateway/detectors/scratch_classifier_model.py)
on data/train.csv. Real training loop: 90/10 train/val split, BCE loss, Adam,
early stopping on val loss. Prints final train/val metrics so numbers in the
README are traceable to this run, not asserted."""
import csv
import random
import sys
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors.scratch_classifier_model import (
    ScratchClassifier, build_vocab, encode, save_artifacts, MAX_SEQ_LEN,
)

RANDOM_SEED = 42
BATCH_SIZE = 32
EPOCHS = 15
LR = 1e-3
PATIENCE = 3


def set_all_seeds(seed: int):
    """Seeds Python's random AND PyTorch's RNG. An earlier version of this
    script only seeded Python's random module (used for data shuffling) --
    torch's own RNG (weight initialization, dropout) was left unseeded, so
    every training run produced a genuinely different model. Caught during
    an audit pass: rerunning scripts/measure_domain_shift.py produced a 40%
    false-positive rate where docs/domain_shift_fix.md documented 30% from
    an earlier run of the exact same process on the exact same data --
    the difference was pure training-run-to-run variance, not a real change.
    That undermines the project's core premise of reproducible, provable
    numbers. Fixed by seeding torch as well; DataLoader(shuffle=True) also
    needs a seeded generator to be fully deterministic, handled below."""
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)  # no-op if no GPU, harmless either way


class TextDataset(Dataset):
    def __init__(self, rows, vocab):
        self.rows = rows
        self.vocab = vocab

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, idx):
        text, label = self.rows[idx]
        ids = encode(text, self.vocab)
        return torch.tensor(ids, dtype=torch.long), torch.tensor(float(label))


def load_train_rows():
    path = REPO_ROOT / "data" / "train.csv"
    rows = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append((row["text"], int(row["label"])))
    return rows


def main():
    set_all_seeds(RANDOM_SEED)
    rng = random.Random(RANDOM_SEED)
    rows = load_train_rows()
    rng.shuffle(rows)

    split_idx = int(len(rows) * 0.9)
    train_rows, val_rows = rows[:split_idx], rows[split_idx:]

    vocab = build_vocab([t for t, _ in train_rows])
    print(f"Vocab size: {len(vocab)}")
    print(f"Train rows: {len(train_rows)}  |  Val rows: {len(val_rows)}")

    train_ds = TextDataset(train_rows, vocab)
    val_ds = TextDataset(val_rows, vocab)
    train_loader = DataLoader(
        train_ds, batch_size=BATCH_SIZE, shuffle=True,
        generator=torch.Generator().manual_seed(RANDOM_SEED),
    )
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)

    model = ScratchClassifier(vocab_size=len(vocab))
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.BCEWithLogitsLoss()

    best_val_loss = float("inf")
    best_state = None
    epochs_without_improvement = 0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        train_loss = 0.0
        for input_ids, labels in train_loader:
            optimizer.zero_grad()
            logits = model(input_ids)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * input_ids.size(0)
        train_loss /= len(train_ds)

        model.eval()
        val_loss = 0.0
        correct = 0
        with torch.no_grad():
            for input_ids, labels in val_loader:
                logits = model(input_ids)
                loss = criterion(logits, labels)
                val_loss += loss.item() * input_ids.size(0)
                preds = (torch.sigmoid(logits) >= 0.5).float()
                correct += (preds == labels).sum().item()
        val_loss /= len(val_ds)
        val_acc = correct / len(val_ds)

        print(f"Epoch {epoch:2d} | train_loss={train_loss:.4f} | val_loss={val_loss:.4f} | val_acc={val_acc:.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= PATIENCE:
                print(f"Early stopping at epoch {epoch} (no val improvement for {PATIENCE} epochs).")
                break

    model.load_state_dict(best_state)
    save_artifacts(model, vocab)
    print(f"Saved best model (val_loss={best_val_loss:.4f}) to models/scratch_classifier/")


if __name__ == "__main__":
    main()
