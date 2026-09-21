"""
Retrain the scratch classifier with diverse external data, as a cumulative ablation, and
measure every step on strictly held-out sets.

Why: threshold recalibration (docs/recalibration-flow.md) could not help because the raw
classifier score barely separates attacks from benign on independent data (ROC-AUC ~0.61 on
deepset test). Fixing that needs a better score, i.e. better training data.

Training configurations (same architecture, hyperparameters, seeds; cumulative):
  v1        shipped: data/train.csv only (jailbreak_llms + regular prompts + in-domain benign)
  A         v1 + deepset/prompt-injections TRAIN split
  B         A  + other injection sources: Lakera/gandalf_ignore_instructions (train),
                 jackhhao/jailbreak-classification (train), xTRam1/safe-guard-prompt-injection
                 (train, stratified sample)
  C         B  + generic benign instructions: yahma/alpaca-cleaned and databricks-dolly-15k
                 (samples)
  C-<src>   leave-one-source-out: C without deepset / safeguard / jackhhao / gandalf. The
            excluded source's own test split is then a genuinely new distribution, which is
            the honest generalisation test (test splits of sources that ARE in training are
            same-distribution and overstate generalisation).

Held-out sets (never trained on; any training text that exactly matches a held-out text is
removed, so exact-duplicate leakage is impossible -- near-duplicates are not detected):
  deepset test | JailbreakBench benign | jailbreak_llms not-in-v1-train | safe-guard test |
  jackhhao test | gandalf test | our own corpus (78 attacks / 17 benign)

Reports, per config and held-out set: detection / false-positive rate at the shipped 0.5
threshold, and ROC-AUC (threshold-free) where both classes exist. Mean over --seeds.

Run: python -X utf8 scripts/retrain_classifier_v2.py [--seeds 3] [--save-best C]
Writes reports/p3_retrain_v2.json
"""
import argparse
import csv
import json
import random
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import yaml
from sklearn.metrics import roc_auc_score
from torch.utils.data import DataLoader

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
csv.field_size_limit(10**9)

from gateway.detectors.scratch_classifier_model import ScratchClassifier, build_vocab, encode  # noqa: E402
from scripts.train_scratch_classifier import BATCH_SIZE, EPOCHS, LR, PATIENCE, TextDataset  # noqa: E402

EXT = REPO_ROOT / "data/external"
norm = lambda t: re.sub(r"\s+", " ", str(t).strip().lower())  # noqa: E731


def _pq(pattern: str) -> pd.DataFrame:
    return pd.read_parquet(next(EXT.glob(pattern)))


def load_sources():
    """Returns (train_sources, heldout_sets). All items are (text, label)."""
    v1 = [(r["text"], int(r["label"])) for r in csv.DictReader(open(REPO_ROOT / "data/train.csv", encoding="utf-8"))]
    ds_tr, ds_te = _pq("prompt-injections/data/train-*.parquet"), _pq("prompt-injections/data/test-*.parquet")
    gd_tr, gd_te = _pq("gandalf_ignore_instructions/data/train-*.parquet"), _pq("gandalf_ignore_instructions/data/test-*.parquet")
    sg_tr, sg_te = _pq("safe-guard-prompt-injection/data/train-*.parquet"), _pq("safe-guard-prompt-injection/data/test-*.parquet")
    jh_tr = pd.read_csv(EXT / "jailbreak-classification/balanced/jailbreak_dataset_train_balanced.csv")
    jh_te = pd.read_csv(EXT / "jailbreak-classification/balanced/jailbreak_dataset_test_balanced.csv")
    rng = random.Random(0)

    sg_s = pd.concat([sg_tr[sg_tr.label == 1].sample(1500, random_state=0), sg_tr[sg_tr.label == 0].sample(1500, random_state=0)])
    alpaca = json.load(open(EXT / "alpaca-cleaned/alpaca_data_cleaned.json", encoding="utf-8"))
    dolly = [json.loads(line) for line in open(EXT / "databricks-dolly-15k/databricks-dolly-15k.jsonl", encoding="utf-8")]
    alp = [(a["instruction"] + (" " + a["input"] if a["input"] else ""), 0) for a in rng.sample(alpaca, 1500)]
    dol = [(d["instruction"], 0) for d in rng.sample(dolly, 1000)]

    train = {
        "v1": v1,
        "deepset_train": [(t, int(label)) for t, label in zip(ds_tr.text, ds_tr.label)],
        "gandalf": [(t, 1) for t in gd_tr.text],
        "jackhhao": [(t, 1 if y == "jailbreak" else 0) for t, y in zip(jh_tr.prompt, jh_tr.type)],
        "safeguard": [(t, int(label)) for t, label in zip(sg_s.text, sg_s.label)],
        "generic_benign": alp + dol,
        "short_benign": [(t, 0) for t in SHORT_BENIGN_TRAIN],
    }
    corpus = yaml.safe_load(open(REPO_ROOT / "corpus/injection_cases.yaml", encoding="utf-8"))
    jbb = [r["Goal"] for r in csv.DictReader(open(EXT / "JBB-Behaviors/data/benign-behaviors.csv", encoding="utf-8"))]
    jb = [r["prompt"] for r in csv.DictReader(open(EXT / "jailbreak_llms/jailbreak_llms-main/data/prompts/jailbreak_prompts_2023_05_07.csv", encoding="utf-8", errors="replace")) if r.get("prompt", "").strip()]
    v1_pos = {norm(t) for t, label in v1 if label == 1}
    held = {
        "deepset_test": [(t, int(label)) for t, label in zip(ds_te.text, ds_te.label)],
        "jbb_benign": [(t, 0) for t in jbb],
        "jbllms_clean": [(p, 1) for p in jb if norm(p) not in v1_pos],
        "safeguard_test": [(t, int(label)) for t, label in zip(sg_te.text, sg_te.label)],
        "jackhhao_test": [(t, 1 if y == "jailbreak" else 0) for t, y in zip(jh_te.prompt, jh_te.type)],
        "gandalf_test": [(t, 1) for t in gd_te.text],
        "short_benign_heldout": [(t, 0) for t in SHORT_BENIGN_HELDOUT],
        "own_corpus": [(c["payload"], 1 if c["expected_behavior"] == "block" else 0) for c in corpus if c["expected_behavior"] in ("block", "allow")],
    }
    return train, held



# Hand-written short conversational benign messages. Found necessary after config C blocked
# "hello" / "thanks" / "ok": the classifier mean-pools token embeddings, so a 1-2 token input is
# dominated by a single embedding, and short chat turns were absent from every training source.
# TRAIN and HELDOUT lists are disjoint; the held-out list measures the failure mode.
SHORT_BENIGN_TRAIN = [
    "hello", "hi", "hey", "hey there", "good morning", "good afternoon", "good evening", "thanks", "thank you",
    "thanks a lot", "thank you so much", "ok", "okay", "sure", "yes", "no", "yep", "nope", "great", "cool",
    "got it", "sounds good", "perfect", "alright", "please", "sorry", "bye", "goodbye", "see you later",
    "have a nice day", "how are you", "how are you?", "what's up", "help", "help me", "can you help me?",
    "I need help", "what can you do?", "who are you?", "what is your name?", "test", "testing", "ping",
    "continue", "go on", "next", "more", "why?", "how?", "what?", "really?", "interesting", "I see",
    "makes sense", "that works", "no problem", "you're welcome", "one moment", "wait", "stop", "start over",
    "what is the status of order 1234?", "show me open purchase orders", "list all suppliers",
    "how many orders are late?", "what is the SLA?", "explain that again", "can you summarise that?",
    "what does this mean?", "tell me more", "give me an example", "what time is it?", "what day is today?",
    "is this correct?", "can you repeat that?", "translate this to French", "hello, how can you help?",
    "hi, I have a question", "hey, quick question", "good morning, can you help me with an order?",
    "thanks, that was helpful", "ok thanks", "ok, thank you", "yes please", "no thanks", "sounds great, thank you",
]
SHORT_BENIGN_HELDOUT = [
    "hiya", "howdy", "greetings", "good night", "many thanks", "cheers", "thx", "ty", "okey", "yeah",
    "nah", "fine", "awesome", "nice", "wonderful", "understood", "roger", "right", "indeed", "of course",
    "hello there", "hi again", "morning", "evening", "what's new?", "how is it going?", "are you there?",
    "can I ask something?", "what are your hours?", "where is my order?", "how do I reset my password?",
    "what is 2 plus 2?", "who won the game?", "can you explain SLAs?", "please continue", "one more question",
    "that's all", "nothing else", "never mind", "sorry, wrong window",
]

_ALL = ["v1", "deepset_train", "gandalf", "jackhhao", "safeguard", "generic_benign"]
CONFIGS = {
    "v1": ["v1"],
    "A": ["v1", "deepset_train"],
    "B": ["v1", "deepset_train", "gandalf", "jackhhao", "safeguard"],
    "C": _ALL,
    # leave-one-source-out: C without one source; that source's TEST split is then a true new-distribution test
    "D": _ALL + ["short_benign"],
    "C-deepset": [k for k in _ALL if k != "deepset_train"],
    "C-safeguard": [k for k in _ALL if k != "safeguard"],
    "C-jackhhao": [k for k in _ALL if k != "jackhhao"],
    "C-gandalf": [k for k in _ALL if k != "gandalf"],
}


def make_train_rows(train, held, config):
    held_texts = {norm(t) for rows in held.values() for t, _ in rows}
    seen, out, dropped_overlap, dropped_conflict = {}, [], 0, 0
    for key in CONFIGS[config]:
        for t, label in train[key]:
            n = norm(t)
            if not n:
                continue
            if n in held_texts:
                dropped_overlap += 1
                continue
            if n in seen:
                dropped_conflict += seen[n] != label
                continue
            seen[n] = label
            out.append((t, label))
    return out, dropped_overlap, int(dropped_conflict)


def train_model(rows, seed):
    random.seed(seed)
    torch.manual_seed(seed)
    rng = random.Random(seed)
    rows = rows[:]
    rng.shuffle(rows)
    cut = int(len(rows) * 0.9)
    tr, va = rows[:cut], rows[cut:]
    vocab = build_vocab([t for t, _ in tr])
    tl = DataLoader(TextDataset(tr, vocab), batch_size=BATCH_SIZE, shuffle=True, generator=torch.Generator().manual_seed(seed))
    vl = DataLoader(TextDataset(va, vocab), batch_size=BATCH_SIZE)
    model = ScratchClassifier(vocab_size=len(vocab))
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    crit = nn.BCEWithLogitsLoss()
    best, best_state, bad = 1e9, None, 0
    for _ in range(EPOCHS):
        model.train()
        for x, y in tl:
            opt.zero_grad()
            crit(model(x), y).backward()
            opt.step()
        model.eval()
        vloss = 0.0
        with torch.no_grad():
            for x, y in vl:
                vloss += crit(model(x), y).item() * x.size(0)
        vloss /= len(va)
        if vloss < best:
            best, best_state, bad = vloss, {k: v.clone() for k, v in model.state_dict().items()}, 0
        else:
            bad += 1
            if bad >= PATIENCE:
                break
    model.load_state_dict(best_state)
    model.eval()
    return model, vocab


def predict(model, vocab, texts):
    out = []
    with torch.no_grad():
        for i in range(0, len(texts), 256):
            ids = torch.tensor([encode(t, vocab) for t in texts[i:i + 256]], dtype=torch.long)
            out.append(torch.sigmoid(model(ids)).numpy())
    return np.concatenate(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--save-best", type=str, default=None, help="config letter to save (seed 0) to models/scratch_classifier_v2")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    train, held = load_sources()
    print({k: len(v) for k, v in held.items()})
    results = {}
    for config in CONFIGS:
        rows, d_ov, d_cf = make_train_rows(train, held, config)
        pos = sum(label for _, label in rows)
        print(f"\n== config {config}: {len(rows)} train rows ({pos} attack / {len(rows) - pos} benign); dropped {d_ov} exact overlaps with held-out sets, {d_cf} label conflicts")
        per_seed = []
        for seed in range(args.seeds):
            model, vocab = train_model(rows, seed)
            m = {}
            for name, items in held.items():
                texts, y = [t for t, _ in items], np.array([label for _, label in items])
                p = predict(model, vocab, texts)
                blocked = p >= 0.5
                r = {}
                if (y == 1).any():
                    r["detection"] = float(blocked[y == 1].mean())
                if (y == 0).any():
                    r["fpr"] = float(blocked[y == 0].mean())
                if len(set(y)) == 2:
                    r["auc"] = float(roc_auc_score(y, p))
                m[name] = r
            per_seed.append(m)
            if args.save_best == config and seed == 0:
                from gateway.detectors.scratch_classifier_model import save_artifacts
                out = REPO_ROOT / "models" / "scratch_classifier_v2"
                save_artifacts(model, vocab, out)
                print(f"  saved seed-0 model to {out}")
        agg = {}
        for name in held:
            agg[name] = {}
            for k in ("detection", "fpr", "auc"):
                vals = [s[name][k] for s in per_seed if k in s[name]]
                if vals:
                    agg[name][k] = {"mean": round(float(np.mean(vals)), 3), "min": round(min(vals), 3), "max": round(max(vals), 3)}
        results[config] = {"n_train": len(rows), "n_attack": int(pos), "dropped_overlap": d_ov, "seeds": args.seeds, "heldout": agg}
        for name, a in agg.items():
            cells = "  ".join(f"{k}={v['mean']:.3f}[{v['min']:.2f}-{v['max']:.2f}]" for k, v in a.items())
            print(f"  {name:<15} {cells}")
    results["heldout_sizes"] = {k: {"n": len(v), "attacks": int(sum(label for _, label in v))} for k, v in held.items()}
    (REPO_ROOT / "reports/p3_retrain_v2.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\nWrote reports/p3_retrain_v2.json")


if __name__ == "__main__":
    main()
