"""
Threshold recalibration against external data, with strict held-out evaluation.

Problem (see README "External benchmark"): at the shipped thresholds the ensemble blocks
~49% of benign deepset/prompt-injections prompts and ~26% of JailbreakBench benign requests.
This script asks: how far can we cut false positives by recalibrating only the decision
thresholds (no retraining), and what does it cost in detection?

Protocol (no test data is used to choose anything):
  CALIBRATION set : deepset/prompt-injections *train* split (546 rows). Thresholds are chosen
                    here: maximise attack detection subject to ensemble FPR <= --max-fpr.
  HELD-OUT sets   : deepset *test* split (116), JailbreakBench benign (100),
                    jailbreak_llms prompts not found in training (244, detection only),
                    and our own hand-written corpus (78 attacks / 17 benign) as a
                    regression check on the domain the gateway was built for.
Policies compared: baseline (shipped thresholds) vs recalibrated (classifier + embedding
thresholds; rule_based is binary and unchanged). Ensemble = block if ANY layer blocks.

Run: python -X utf8 scripts/recalibrate_thresholds.py [--max-fpr 0.05]
Writes reports/p3_recalibration.json (includes score-level ROC points for plotting).
"""
import argparse
import csv
import json
import math
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
csv.field_size_limit(10**9)

from gateway.detectors import rule_based  # noqa: E402
from gateway.detectors.classifier import CLASSIFIER_THRESHOLD, ScratchClassifierDetector  # noqa: E402
from gateway.detectors.embedding_similarity import SIMILARITY_THRESHOLD, EmbeddingSimilarityDetector  # noqa: E402

EXT = REPO_ROOT / "data/external"
norm = lambda t: re.sub(r"\s+", " ", t.strip().lower())  # noqa: E731


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p, d = k / n, 1 + z * z / n
    c, h = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0, (c - h) / d), 3), round(min(1, (c + h) / d), 3)]


class Scorer:
    def __init__(self):
        self.emb = EmbeddingSimilarityDetector(); self.emb.load()
        self.clf = ScratchClassifierDetector(); self.clf.load()

    def scores(self, texts):
        rb, ce, cc = [], [], []
        for t in texts:
            rb.append(bool(rule_based.detect(t).blocked))
            ce.append(self.emb.detect(t).confidence)
            cc.append(self.clf.detect(t).confidence)
        return {"rule": np.array(rb), "emb": np.array(ce), "clf": np.array(cc)}


def blocked(sc, t_clf, t_emb):
    return sc["rule"] | (sc["clf"] >= t_clf) | (sc["emb"] >= t_emb)


def rate(flags):
    k, n = int(flags.sum()), len(flags)
    return {"k": k, "n": n, "rate": round(k / n, 3), "ci95": wilson(k, n)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-fpr", type=float, default=0.05)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    scorer = Scorer()

    # ---- data ----
    train_all = {norm(r["text"]) for r in csv.DictReader(open(REPO_ROOT / "data/train.csv", encoding="utf-8"))}
    train_pos = {norm(r["text"]) for r in csv.DictReader(open(REPO_ROOT / "data/train.csv", encoding="utf-8")) if r["label"] == "1"}
    dd = EXT / "prompt-injections/data"
    ds_train = pd.read_parquet(next(dd.glob("train-*.parquet")))
    ds_test = pd.read_parquet(next(dd.glob("test-*.parquet")))
    jbb = [r["Goal"] for r in csv.DictReader(open(EXT / "JBB-Behaviors/data/benign-behaviors.csv", encoding="utf-8"))]
    jb = [r["prompt"] for r in csv.DictReader(open(EXT / "jailbreak_llms/jailbreak_llms-main/data/prompts/jailbreak_prompts_2023_05_07.csv", encoding="utf-8", errors="replace")) if r.get("prompt", "").strip()]
    jb_clean = [p for p in jb if norm(p) not in train_pos]
    corpus = yaml.safe_load(open(REPO_ROOT / "corpus/injection_cases.yaml", encoding="utf-8"))
    c_atk = [c["payload"] for c in corpus if c["expected_behavior"] == "block"]
    c_ben = [c["payload"] for c in corpus if c["expected_behavior"] == "allow"]
    # the calibration/test split must not share text
    assert not (set(map(norm, ds_train["text"])) & set(map(norm, ds_test["text"]))), "deepset train/test overlap"

    S = {
        "cal_attack": scorer.scores(ds_train.loc[ds_train.label == 1, "text"].tolist()),
        "cal_benign": scorer.scores(ds_train.loc[ds_train.label == 0, "text"].tolist()),
        "deepset_test_attack": scorer.scores(ds_test.loc[ds_test.label == 1, "text"].tolist()),
        "deepset_test_benign": scorer.scores(ds_test.loc[ds_test.label == 0, "text"].tolist()),
        "jbb_benign": scorer.scores(jbb),
        "jbllms_clean_attack": scorer.scores(jb_clean),
        "corpus_attack": scorer.scores(c_atk),
        "corpus_benign": scorer.scores(c_ben),
    }
    print({k: len(v["clf"]) for k, v in S.items()})

    # ---- choose thresholds on the calibration set only ----
    grid_c = [round(x, 3) for x in np.concatenate([np.arange(0.05, 0.99, 0.01), [0.99, 0.995, 0.999, 1.01]])]
    grid_e = [round(x, 2) for x in list(np.arange(0.05, 1.0, 0.05)) + [1.01]]

    def choose(max_fpr):
        best = None
        for tc in grid_c:
            for te in grid_e:
                fpr = blocked(S["cal_benign"], tc, te).mean()
                if fpr <= max_fpr:
                    det = blocked(S["cal_attack"], tc, te).mean()
                    key = (det, tc, te)  # ties -> higher thresholds (fewer blocks)
                    if best is None or key > best[0]:
                        best = (key, tc, te, det, fpr)
        return best

    _, t_clf, t_emb, cal_det, cal_fpr = choose(args.max_fpr)
    print(f"\nChosen on calibration set (FPR <= {args.max_fpr:.0%}): clf>={t_clf}, emb>={t_emb}  ->  cal detection {cal_det:.1%}, cal FPR {cal_fpr:.1%}")

    # score separability on held-out deepset test: threshold-free, so shows the ceiling for ANY recalibration
    from sklearn.metrics import roc_auc_score
    y = np.r_[np.ones(len(S["deepset_test_attack"]["clf"])), np.zeros(len(S["deepset_test_benign"]["clf"]))]
    auc = {k: round(float(roc_auc_score(y, np.r_[S["deepset_test_attack"][k], S["deepset_test_benign"][k]])), 3) for k in ("clf", "emb")}
    yc = np.r_[np.ones(len(S["corpus_attack"]["clf"])), np.zeros(len(S["corpus_benign"]["clf"]))]
    auc_corpus = {k: round(float(roc_auc_score(yc, np.r_[S["corpus_attack"][k], S["corpus_benign"][k]])), 3) for k in ("clf", "emb")}
    print(f"ROC-AUC of raw scores  deepset-test: {auc}   our corpus: {auc_corpus}")

    frontier = []
    for mf in (0.02, 0.05, 0.10, 0.20, 0.30, 0.50):
        _, tc, te, cd, cf = choose(mf)
        row = {"max_fpr_on_cal": mf, "clf": tc, "emb": te,
               "deepset_test_detection": rate(blocked(S["deepset_test_attack"], tc, te))["rate"],
               "deepset_test_fpr": rate(blocked(S["deepset_test_benign"], tc, te))["rate"],
               "jbb_fpr": rate(blocked(S["jbb_benign"], tc, te))["rate"],
               "jbllms_clean_detection": rate(blocked(S["jbllms_clean_attack"], tc, te))["rate"],
               "corpus_detection": rate(blocked(S["corpus_attack"], tc, te))["rate"],
               "corpus_fpr": rate(blocked(S["corpus_benign"], tc, te))["rate"]}
        frontier.append(row)
        print(f"  frontier FPR<={mf:.0%}: clf>={tc} emb>={te} | deepset det {row['deepset_test_detection']:.0%} fpr {row['deepset_test_fpr']:.0%} | jbb fpr {row['jbb_fpr']:.0%} | jbllms det {row['jbllms_clean_detection']:.0%} | corpus det {row['corpus_detection']:.0%} fpr {row['corpus_fpr']:.0%}")

    policies = {
        "baseline (shipped)": (CLASSIFIER_THRESHOLD, SIMILARITY_THRESHOLD),
        "recalibrated": (t_clf, t_emb),
    }
    sets = [("deepset_test_attack", "detection"), ("deepset_test_benign", "false-positive"),
            ("jbb_benign", "false-positive"), ("jbllms_clean_attack", "detection"),
            ("corpus_attack", "detection"), ("corpus_benign", "false-positive")]
    results = {"roc_auc_deepset_test": auc, "roc_auc_own_corpus": auc_corpus, "frontier": frontier, "max_fpr": args.max_fpr, "chosen": {"classifier": t_clf, "embedding": t_emb, "cal_detection": round(float(cal_det), 3), "cal_fpr": round(float(cal_fpr), 3)}, "policies": {}}
    for pname, (tc, te) in policies.items():
        results["policies"][pname] = {"thresholds": {"classifier": tc, "embedding": te}}
        print(f"\n{pname}: classifier>={tc}, embedding>={te}")
        for sname, kind in sets:
            r = rate(blocked(S[sname], tc, te))
            results["policies"][pname][sname] = r
            print(f"  {sname:<22} {kind:<15} {r['k']:>4}/{r['n']:<4} {r['rate']:>6.1%}  CI {r['ci95']}")

    # ---- ROC-style curve on the held-out deepset test (for plotting; NOT used to pick thresholds) ----
    curve = []
    for tc in [round(x, 3) for x in np.concatenate([np.arange(0.0, 1.0, 0.02), [0.99, 0.999, 1.01]])]:
        te = t_emb if False else SIMILARITY_THRESHOLD
        curve.append({"clf_threshold": tc,
                      "deepset_test_detection": float(blocked(S["deepset_test_attack"], tc, te).mean()),
                      "deepset_test_fpr": float(blocked(S["deepset_test_benign"], tc, te).mean()),
                      "jbb_fpr": float(blocked(S["jbb_benign"], tc, te).mean()),
                      "corpus_detection": float(blocked(S["corpus_attack"], tc, te).mean())})
    results["curve_classifier_only_sweep"] = curve
    (REPO_ROOT / "reports/p3_recalibration.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\nWrote reports/p3_recalibration.json")


if __name__ == "__main__":
    main()
