"""
Phase 2, step 1: is the TF-IDF similarity layer earning its place in the default ensemble?

Scores every component once per example on the standard held-out sets, then evaluates
block-on-any compositions, so the only thing that changes between rows is which layers are
in the OR. Components:
  rule    rule_based (binary)
  tfidf   TF-IDF similarity, shipped default (threshold 0.35)
  st      sentence-transformer (all-MiniLM-L6-v2, fp32) similarity, opt-in backend (threshold 0.45)
  clf     numpy classifier with the short-input guard (threshold 0.5), shipped layer 3
  guard   ProtectAI DeBERTa (threshold 0.5), reference only: does not fit the 512 MB free tier

Compositions marked (reference) are not deployable on the free tier; they show what each layer
contributes. Detection / false-positive rate with Wilson 95% CIs. Sets and caveats as in
docs/guard-baselines.md (17 benign own-corpus cases; TF-IDF/ST indexes fit on jailbreak_llms-derived
positives, so jailbreak-style sets flatter them).

Run: python -X utf8 -m scripts.baselines.ensemble_ablation
Writes reports/p3_ensemble_ablation.json
"""
import json
import sys
import time
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors import rule_based  # noqa: E402
from gateway.detectors.classifier_numpy import ScratchClassifierDetectorNumpy  # noqa: E402
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector  # noqa: E402
from gateway.detectors.embedding_similarity_st import SentenceTransformerSimilarityDetector  # noqa: E402
from scripts.baselines.run_guard_baselines import MODELS, SETS, guard_scores, load_guard, set_metrics  # noqa: E402
from scripts.retrain_classifier_v2 import load_sources  # noqa: E402

COMPOSITIONS = {
    "rule | tfidf | clf   (shipped)": ("rule", "tfidf", "clf"),
    "rule | clf           (TF-IDF removed)": ("rule", "clf"),
    "rule | st | clf      (ST replaces TF-IDF)": ("rule", "st", "clf"),
    "rule | guard         (reference)": ("rule", "guard"),
    "rule | clf | guard   (reference)": ("rule", "clf", "guard"),
    "rule | tfidf | clf | guard (reference)": ("rule", "tfidf", "clf", "guard"),
}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    _, held = load_sources()
    tfidf = EmbeddingSimilarityDetector(); tfidf.load()
    st = SentenceTransformerSimilarityDetector(); st.load()
    clf = ScratchClassifierDetectorNumpy(); clf.load()
    tok, model, idx, _ = load_guard(MODELS[0])

    comp = {}
    for name in SETS:
        texts = [t for t, _ in held[name]]
        comp[name] = {
            "y": np.array([label for _, label in held[name]]),
            "rule": np.array([rule_based.detect(t).blocked for t in texts]),
            "tfidf": np.array([tfidf.detect(t).blocked for t in texts]),
            "st": np.array([st.detect(t).blocked for t in texts]),
            "clf": np.array([clf.detect(t).blocked for t in texts]),
            "guard": guard_scores(tok, model, idx, texts) >= 0.5,
        }

    out = {"sets": {k: {"n": len(v["y"]), "attacks": int(v["y"].sum())} for k, v in comp.items()}, "compositions": {}, "single_layers": {}}
    for label, layers in COMPOSITIONS.items():
        out["compositions"][label] = {}
        for name, c in comp.items():
            blocked = np.logical_or.reduce([c[layer] for layer in layers])
            out["compositions"][label][name] = set_metrics(blocked, c["y"])
    for layer in ("rule", "tfidf", "st", "clf", "guard"):
        out["single_layers"][layer] = {name: set_metrics(c[layer], c["y"]) for name, c in comp.items()}

    # p50 single-example latency of the deployable compositions, short-circuiting like the middleware does
    pool = [t for name in SETS for t, _ in held[name]]
    sample = [pool[i] for i in np.random.default_rng(0).choice(len(pool), 120, replace=False)]

    def p50(fn):
        lat = []
        for t in sample:
            t0 = time.perf_counter()
            fn(t)
            lat.append((time.perf_counter() - t0) * 1000)
        return round(float(np.median(lat)), 3)

    out["p50_latency_ms"] = {
        "rule | tfidf | clf": p50(lambda t: bool(rule_based.detect(t).blocked) or bool(tfidf.detect(t).blocked) or bool(clf.detect(t).blocked)),
        "rule | clf": p50(lambda t: bool(rule_based.detect(t).blocked) or bool(clf.detect(t).blocked)),
        "rule | st | clf": p50(lambda t: bool(rule_based.detect(t).blocked) or bool(st.detect(t).blocked) or bool(clf.detect(t).blocked)),
    }
    (REPO_ROOT / "reports/p3_ensemble_ablation.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    def cell(m):
        det = f"{m['detection']['rate']:.0%}" if "detection" in m else "-"
        fpr = f"{m['fpr']['rate']:.0%}" if "fpr" in m else "-"
        return f"{det}/{fpr}"

    print("cells are detection/FPR ('-' = not applicable to that set)")
    print(f"{'composition':<44}" + "".join(f"{s[:13]:<15}" for s in SETS))
    for label in COMPOSITIONS:
        print(f"{label:<44}" + "".join(f"{cell(out['compositions'][label][s]):<15}" for s in SETS))
    print("\nsingle layers")
    for layer, d in out["single_layers"].items():
        print(f"{layer:<44}" + "".join(f"{cell(d[s]):<15}" for s in SETS))
    print("\nWrote reports/p3_ensemble_ablation.json")


if __name__ == "__main__":
    main()
