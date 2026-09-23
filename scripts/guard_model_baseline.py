"""
Guard-model baseline: how does our from-scratch 3-layer ensemble compare to a published,
purpose-built prompt-injection classifier that a team could just... use instead?

Named as the single biggest credibility gap in an external skills review of this project:
building a detector from scratch is a fine learning exercise, but the market has existing
guard models, and a portfolio that claims "detection" without comparing against one invites
the obvious question "why not just use Prompt Guard / a HF guard model?"

Baseline model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0, ungated, 184M
params, purpose-trained for exactly this task). meta-llama/Llama-Prompt-Guard-2-86M was also
considered but is gated behind a manual Meta license approval on Hugging Face -- not something
this script can pull automatically, so it is left as a documented follow-up, not silently
skipped.

Scored on the SAME held-out sets already used for the classifier retrain
(scripts/retrain_classifier_v2.py, docs/retraining-flow.md), so the numbers are directly
comparable to our shipped ensemble's numbers in reports/p3_shipped_heldout.json:
  deepset test | JailbreakBench benign | jailbreak_llms clean | own corpus

Latency is measured on this CPU, single-example inference (no batching), same as our
detectors' own latency numbers -- an apples-to-apples comparison, not a best-case GPU number.

Run: python -X utf8 -m scripts.guard_model_baseline
Writes reports/p3_guard_baseline.json
"""
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.retrain_classifier_v2 import load_sources  # noqa: E402

MODEL_DIR = REPO_ROOT / "data/external/deberta-v3-base-prompt-injection-v2"
SETS = ("deepset_test", "jbb_benign", "jbllms_clean", "short_benign_heldout", "in_domain_heldout", "own_corpus")


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p, d = k / n, 1 + z * z / n
    c, h = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0, (c - h) / d), 3), round(min(1, (c + h) / d), 3)]


def load_guard():
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.eval()
    id2label = {int(k): v for k, v in model.config.id2label.items()}
    injection_idx = next(i for i, lbl in id2label.items() if "inject" in lbl.lower() or lbl in ("1", "LABEL_1"))
    return tok, model, injection_idx


def predict(tok, model, injection_idx, texts, batch_size=16):
    probs, latencies = [], []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            t0 = time.perf_counter()
            enc = tok(batch, return_tensors="pt", truncation=True, padding=True, max_length=512)
            logits = model(**enc).logits
            p = torch.softmax(logits, dim=-1)[:, injection_idx].numpy()
            dt = (time.perf_counter() - t0) * 1000 / len(batch)
            probs.extend(p.tolist())
            latencies.extend([dt] * len(batch))
    return np.array(probs), np.array(latencies)


def rate(flags):
    k, n = int(flags.sum()), len(flags)
    return {"k": k, "n": n, "rate": round(k / n, 3), "ci95": wilson(k, n)}


def main():
    if not MODEL_DIR.exists():
        sys.exit(f"Model not found at {MODEL_DIR}. Download with:\n"
                  f'  python -c "from huggingface_hub import snapshot_download as s; '
                  f's(\'protectai/deberta-v3-base-prompt-injection-v2\', local_dir=\'{MODEL_DIR.as_posix()}\')"')
    sys.stdout.reconfigure(encoding="utf-8")
    tok, model, injection_idx = load_guard()
    _, held = load_sources()

    shipped = json.loads((REPO_ROOT / "reports/p3_shipped_heldout.json").read_text(encoding="utf-8"))

    out = {"model": "protectai/deberta-v3-base-prompt-injection-v2", "threshold": 0.5,
           "note_on_meta_prompt_guard_2": "meta-llama/Llama-Prompt-Guard-2-86M is gated behind manual Meta license approval on Hugging Face; not evaluated here."}
    print(f"{'Set':<20} {'Guard detection':<24} {'Guard FPR':<24} {'Guard avg ms':<14} {'Shipped ensemble detection':<28} {'Shipped ensemble FPR'}")
    for name in SETS:
        if name not in held:
            continue
        items = held[name]
        texts, y = [t for t, _ in items], np.array([label for _, label in items])
        probs, lat = predict(tok, model, injection_idx, texts)
        blocked = probs >= 0.5
        row = {"n": len(items), "avg_latency_ms": round(float(lat.mean()), 3)}
        if (y == 1).any():
            row["detection"] = rate(blocked[y == 1])
        if (y == 0).any():
            row["fpr"] = rate(blocked[y == 0])
        out[name] = row
        ship = shipped.get(name, {}).get("ensemble_shipped", {})
        det_s = f"{row['detection']['rate']:.1%} ({row['detection']['k']}/{row['detection']['n']})" if "detection" in row else "n/a"
        fpr_s = f"{row['fpr']['rate']:.1%} ({row['fpr']['k']}/{row['fpr']['n']})" if "fpr" in row else "n/a"
        ship_det = f"{ship['detection']['rate']:.1%}" if "detection" in ship else "n/a"
        ship_fpr = f"{ship['fpr']['rate']:.1%}" if "fpr" in ship else "n/a"
        print(f"{name:<20} {det_s:<24} {fpr_s:<24} {row['avg_latency_ms']:<14} {ship_det:<28} {ship_fpr}")

    (REPO_ROOT / "reports/p3_guard_baseline.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\nWrote reports/p3_guard_baseline.json")


if __name__ == "__main__":
    main()
