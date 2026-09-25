"""
DistilBERT fine-tune -- the "real" Layer 3 the build doc originally asked for.

STATUS (2026-09-11): the original build environment for this project could not
reach huggingface.co or any other host serving pretrained weights (see
docs/decisions.md, 2026-09-05 entries). Re-checked from the current
environment: huggingface.co is reachable. Benchmarked a real training step
before running the full script (see docs/decisions.md, 2026-09-11) -- ~2,020
training rows at batch 32 is a ~15-20 minute CPU job, not the multi-hour one a
naive line-count of data/train.csv would have suggested. Results of the actual
run are recorded in docs/comparison_table.md and docs/decisions.md once
complete -- read those for the real numbers rather than the "expected result"
paragraph below, which was a prediction made before this ever ran.

What has run since the beginning of this project is
gateway/detectors/scratch_classifier_model.py, trained from scratch (random
embedding init, no pretrained knowledge) -- see docs/comparison_table.md and
docs/domain_shift_fix.md for its real, measured numbers. This script fine-tunes
a genuinely pretrained checkpoint instead, for a fair apples-to-apples
comparison on the identical train/eval split.

To run it yourself:
  1. Network access to huggingface.co (this repo's own environment now has it;
     a restricted sandbox may not).
  2. pip install -r requirements.txt, then uncomment the `transformers` and
     `datasets` lines (or `pip install ".[finetune]"`).
  3. python scripts/train_distilbert_finetune.py
  4. Compare its printed precision/recall/latency against
     docs/comparison_table.md's scratch_classifier row on the SAME
     data/eval.csv.

Original prediction (kept for the record, not as a substitute for the actual
result above): a real DistilBERT fine-tune should meaningfully outperform the
from-scratch classifier on the domain-mismatch false-positive problem
documented in docs/domain_shift_fix.md, because pretrained language
understanding generalizes from far fewer in-domain examples than an embedding
matrix trained from scratch. Whether that held is in the actual run's numbers,
not in this paragraph.
"""
import csv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

MODEL_CHECKPOINT = "distilbert-base-uncased"
MODEL_REVISION = "12040accade4e8a0f71eabdb258fecc2e7e948be"      # pinned hub commit of distilbert-base-uncased (2024-05-06)
MAX_LENGTH = 128
BATCH_SIZE = 32  # bumped from the original 16 -- benchmarked faster on this
                 # CPU (20 threads) without changing what's being measured
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

    tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT, revision=MODEL_REVISION)

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
        MODEL_CHECKPOINT, num_labels=2, revision=MODEL_REVISION,
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

    # --- Same methodology as scripts/evaluate.py, so this is a genuinely
    # apples-to-apples 4th row in docs/comparison_table.md: per-case single-
    # example latency (not batched), detection rate = recall on
    # expected_behavior=="block", false-positive rate = block rate on
    # expected_behavior=="allow", GW-018/GW-036 (flag) reported separately. ---
    import time
    model.eval()
    eval_case_rows = []
    with open(REPO_ROOT / "data" / "eval.csv", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            eval_case_rows.append(row)

    results = []
    for row in eval_case_rows:
        t0 = time.perf_counter()
        enc = tokenizer(row["text"], truncation=True, padding="max_length",
                         max_length=MAX_LENGTH, return_tensors="pt")
        with torch.no_grad():
            logits = model(**enc).logits
        probs = torch.softmax(logits, dim=-1)[0]
        blocked = bool(torch.argmax(logits, dim=-1).item() == 1)
        latency_ms = (time.perf_counter() - t0) * 1000
        results.append({
            "case_id": row["case_id"], "expected_behavior": row["expected_behavior"],
            "blocked": blocked, "confidence": float(probs[1]), "latency_ms": latency_ms,
        })

    should_block = [r for r in results if r["expected_behavior"] == "block"]
    should_allow = [r for r in results if r["expected_behavior"] == "allow"]
    ambiguous = [r for r in results if r["expected_behavior"] == "flag"]
    detection_rate = sum(1 for r in should_block if r["blocked"]) / len(should_block) if should_block else float("nan")
    fp_rate = sum(1 for r in should_allow if r["blocked"]) / len(should_allow) if should_allow else float("nan")
    avg_latency_ms = sum(r["latency_ms"] for r in results) / len(results)
    missed = [r["case_id"] for r in should_block if not r["blocked"]]
    false_positives = [r["case_id"] for r in should_allow if r["blocked"]]
    ambiguous_decisions = [(r["case_id"], r["blocked"]) for r in ambiguous]

    print(f"\n=== scripts/evaluate.py-equivalent scoring on data/eval.csv ===")
    print(f"detection_rate={detection_rate:.2%} ({len(should_block) - len(missed)}/{len(should_block)})")
    print(f"false_positive_rate={fp_rate:.2%} ({len(false_positives)}/{len(should_allow)})")
    print(f"avg_latency_ms={avg_latency_ms:.3f}")
    print(f"missed={missed}")
    print(f"false_positives={false_positives}")
    print(f"ambiguous(GW-018/GW-036)={ambiguous_decisions}")

    result_summary = {
        "detection_rate": detection_rate, "n_should_block": len(should_block), "n_missed": len(missed),
        "false_positive_rate": fp_rate, "n_should_allow": len(should_allow), "n_false_positives": len(false_positives),
        "avg_latency_ms": avg_latency_ms, "missed": missed, "false_positives": false_positives,
        "ambiguous": ambiguous_decisions, "trainer_eval_metrics": metrics,
    }
    import json
    out_path = REPO_ROOT / "docs" / "distilbert_finetune_raw_result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result_summary, f, indent=2)
    print(f"\nRaw result written to {out_path} -- see docs/distilbert_finetune_result.md "
          f"for the write-up and docs/comparison_table.md for the added row.")


if __name__ == "__main__":
    main()
