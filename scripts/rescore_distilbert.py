"""
Re-scores the already-trained DistilBERT fine-tune (models/distilbert_finetuned/final,
see docs/distilbert_finetune_result.md) against the current data/eval.csv --
inference only, no retraining. Exists because the corpus grew from 36 to 72
cases (docs/decisions.md, 2026-09-12) after that model was trained, and its
comparison_table.md row would otherwise silently describe the OLD, smaller
eval set while every other row in the same table was updated to the new one.

Same scoring methodology as scripts/evaluate.py (recall on expected_behavior==
block, block-rate on expected_behavior==allow, flag cases reported separately).
"""
import sys
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

MODEL_PATH = REPO_ROOT / "models" / "distilbert_finetuned" / "final"


def main():
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    if not MODEL_PATH.exists():
        raise SystemExit(f"{MODEL_PATH} doesn't exist -- run "
                          "scripts/train_distilbert_finetune.py first.")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    model.eval()

    with open(REPO_ROOT / "corpus" / "injection_cases.yaml", encoding="utf-8") as f:
        cases = yaml.safe_load(f)

    detection_tp = detection_total = 0
    fp = fp_total = 0
    latencies = []
    missed, false_positives, flag_results = [], [], {}

    for case in cases:
        text, expected = case["payload"], case["expected_behavior"]
        t0 = time.perf_counter()
        enc = tokenizer(text, truncation=True, padding="max_length", max_length=128, return_tensors="pt")
        with torch.no_grad():
            blocked = bool(torch.argmax(model(**enc).logits, dim=-1).item() == 1)
        latencies.append((time.perf_counter() - t0) * 1000)

        if expected == "block":
            detection_total += 1
            if blocked:
                detection_tp += 1
            else:
                missed.append(case["id"])
        elif expected == "allow":
            fp_total += 1
            if blocked:
                fp += 1
                false_positives.append(case["id"])
        elif expected == "flag":
            flag_results[case["id"]] = blocked

    print(f"detection_rate={detection_tp}/{detection_total} ({detection_tp/detection_total:.2%})")
    print(f"false_positive_rate={fp}/{fp_total} ({fp/fp_total:.2%})")
    print(f"avg_latency_ms={sum(latencies)/len(latencies):.3f}")
    print(f"missed={missed}")
    print(f"false_positives={false_positives}")
    print(f"flag_results={flag_results}")


if __name__ == "__main__":
    main()
