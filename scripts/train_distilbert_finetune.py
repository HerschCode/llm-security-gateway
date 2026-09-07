"""
DEFERRED SCRIPT -- HAS NEVER BEEN RUN. READ THIS BEFORE TRUSTING ANYTHING BELOW.

This is the "real" Layer 3 the build doc originally asked for: fine-tuning a
pretrained DistilBERT checkpoint on injection-vs-benign data. It is written
correctly (to the best of my knowledge, following standard HF fine-tuning
patterns) but has NEVER BEEN EXECUTED, because this sandbox cannot reach
huggingface.co or any other host that serves pretrained model weights (see
docs/decisions.md, 2026-09-05 entries -- checked huggingface.co, hf-mirror.com,
objects.githubusercontent.com, download.pytorch.org, all blocked).

What actually runs and is proven in this repo is
gateway/detectors/scratch_classifier_model.py, trained from scratch (random
embedding init, no pretrained knowledge) -- see docs/comparison_table.md and
docs/domain_shift_fix.md for its real, measured numbers.

To actually run this script:
  1. Move to a machine/environment with network access to huggingface.co
     (a laptop, Colab, an EC2 instance -- anywhere without this sandbox's
     allowlist restriction).
  2. pip install -r requirements.txt (uncomment the `transformers` and
     `datasets` lines, or `pip install ".[finetune]"` if using pyproject.toml)
  3. Run: python scripts/train_distilbert_finetune.py
  4. Compare its printed precision/recall/latency against
     docs/comparison_table.md's scratch_classifier row, on the SAME
     data/eval.csv, and add a fourth row honestly -- don't guess the numbers
     ahead of actually running this.

Expected qualitative result (a prediction, not a measurement): a real
DistilBERT fine-tune should meaningfully outperform the from-scratch
classifier on the domain-mismatch false-positive problem documented in
docs/domain_shift_fix.md, because pretrained language understanding
generalizes from far fewer in-domain examples than an embedding matrix
trained from scratch on this project's ~2,050 training rows. Whether that
prediction actually holds is exactly what running this script would tell you
-- until then, treat it as a hypothesis, not a result.
"""
import csv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

MODEL_CHECKPOINT = "distilbert-base-uncased"
MAX_LENGTH = 128
BATCH_SIZE = 16
EPOCHS = 3
LEARNING_RATE = 2e-5


def load_data():
    """Same train/eval split used by the from-scratch classifier, for a fair
    apples-to-apples comparison."""
    train_rows, eval_rows = [], []
    with open(REPO_ROOT / "data" / "train.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            train_rows.append((row["text"], int(row["label"])))
    with open(REPO_ROOT / "data" / "eval.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            eval_rows.append((row["text"], int(row["label"]), row["case_id"]))
    return train_rows, eval_rows


def main():
    # Imports deferred to inside main() so this file can still be imported/read
    # (e.g. by a linter or by someone browsing the repo) without immediately
    # crashing on a missing dependency in this sandbox.
    try:
        import torch
        from torch.utils.data import Dataset
        from transformers import (
            AutoTokenizer, AutoModelForSequenceClassification,
            Trainer, TrainingArguments,
        )
    except ImportError as e:
        raise SystemExit(
            "transformers/datasets not installed. This script is meant to run "
            "in an environment with model-hub access -- see this file's module "
            "docstring for setup instructions. Original error: " + str(e)
        )

    train_rows, eval_rows = load_data()

    tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)

    class InjectionDataset(Dataset):
        def __init__(self, rows):
            self.rows = rows

        def __len__(self):
            return len(self.rows)

        def __getitem__(self, idx):
            text, label = self.rows[idx][0], self.rows[idx][1]
            encoding = tokenizer(
                text, truncation=True, padding="max_length", max_length=MAX_LENGTH,
                return_tensors="pt",
            )
            return {
                "input_ids": encoding["input_ids"].squeeze(0),
                "attention_mask": encoding["attention_mask"].squeeze(0),
                "labels": torch.tensor(label, dtype=torch.long),
            }

    train_dataset = InjectionDataset(train_rows)
    eval_dataset = InjectionDataset([(t, l) for t, l, _ in eval_rows])

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_CHECKPOINT, num_labels=2,
    )

    training_args = TrainingArguments(
        output_dir=str(REPO_ROOT / "models" / "distilbert_finetuned"),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        logging_steps=10,
    )

    def compute_metrics(eval_pred):
        import numpy as np
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()
        tn = ((preds == 0) & (labels == 0)).sum()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {"precision": precision, "recall": recall, "false_positive_rate": fp_rate}

    trainer = Trainer(
        model=model, args=training_args,
        train_dataset=train_dataset, eval_dataset=eval_dataset,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()
    print("Final eval metrics:", metrics)

    model.save_pretrained(REPO_ROOT / "models" / "distilbert_finetuned" / "final")
    tokenizer.save_pretrained(REPO_ROOT / "models" / "distilbert_finetuned" / "final")


if __name__ == "__main__":
    main()
