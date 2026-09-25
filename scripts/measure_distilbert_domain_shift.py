"""
Tests the fine-tuned DistilBERT model (scripts/train_distilbert_finetune.py)
against the SAME held-out in-domain benign query set used to measure the
scratch classifier's domain-shift false-positive rate
(scripts/measure_domain_shift.py, docs/domain_shift_fix.md: 60% -> 10% after
the fix). This is the actual test of that script's central hypothesis --
"pretrained language understanding should generalize better from few examples
than an embedding matrix trained from scratch" -- which the standard 36-case
corpus's false-positive rate (only 4 "should allow" cases) is too small a
sample to speak to.

Requires models/distilbert_finetuned/final to exist -- run
scripts/train_distilbert_finetune.py first.
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
BENIGN_QUERIES_PATH = REPO_ROOT / "corpus" / "benign_indomain_queries.yaml"
MODEL_PATH = REPO_ROOT / "models" / "distilbert_finetuned" / "final"


def load_benign_eval_texts():
    with open(BENIGN_QUERIES_PATH, encoding="utf-8") as f:
        cases = yaml.safe_load(f)
    return [c["text"] for c in cases if c["split"] == "eval"]


def main():
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    if not MODEL_PATH.exists():
        raise SystemExit(f"{MODEL_PATH} doesn't exist -- run "
                          "scripts/train_distilbert_finetune.py first.")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)  # nosec B615 - a local fine-tuned checkpoint, not a hub download
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)  # nosec B615 - a local fine-tuned checkpoint, not a hub download
    model.eval()

    texts = load_benign_eval_texts()
    blocked_texts = []
    for text in texts:
        enc = tokenizer(text, truncation=True, padding="max_length", max_length=128, return_tensors="pt")
        with torch.no_grad():
            logits = model(**enc).logits
        blocked = bool(torch.argmax(logits, dim=-1).item() == 1)
        if blocked:
            blocked_texts.append(text)

    fp_rate = len(blocked_texts) / len(texts) if texts else float("nan")
    print(f"DistilBERT domain-shift false-positive rate: {len(blocked_texts)}/{len(texts)} "
          f"({fp_rate:.0%})")
    if blocked_texts:
        print("Incorrectly blocked:")
        for t in blocked_texts:
            print(f"  - {t!r}")
    print("\nCompare against scripts/measure_domain_shift.py's scratch-classifier "
          "result in docs/domain_shift_fix.md (1/10, 10%, after the fix).")


if __name__ == "__main__":
    main()
