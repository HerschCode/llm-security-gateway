"""
Evaluates the SHIPPED serving path (rule_based + TF-IDF embedding + numpy classifier with the
short-input guard, block-on-any) on the held-out sets defined in scripts/retrain_classifier_v2.py,
per layer and for the ensemble, with Wilson 95% CIs. Compares against the v1 classifier kept in
models/scratch_classifier_v1 (same layers, same guard) so the classifier change is isolated.

Caveats (also in docs/retraining-flow.md): the TF-IDF embedding layer's index was fit on v1
training positives (jailbreak_llms), so its numbers on jailbreak-style held-out sets may be
inflated by near-duplicates; own_corpus is small (78 attacks / 17 benign).
Run: python -X utf8 -m scripts.evaluate_shipped_heldout   -> reports/p3_shipped_heldout.json
"""
import json
import math
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors import rule_based  # noqa: E402
from gateway.detectors.classifier_numpy import ScratchClassifierDetectorNumpy, load_numpy_artifacts  # noqa: E402
from gateway.detectors.embedding_similarity import EmbeddingSimilarityDetector  # noqa: E402
from scripts.retrain_classifier_v2 import load_sources  # noqa: E402


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p, d = k / n, 1 + z * z / n
    c, h = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0, (c - h) / d), 3), round(min(1, (c + h) / d), 3)]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    _, held = load_sources()
    emb = EmbeddingSimilarityDetector(); emb.load()
    detectors = {}
    for tag, path in (("classifier_v1", REPO_ROOT / "models/scratch_classifier_v1"), ("classifier_shipped", None)):
        d = ScratchClassifierDetectorNumpy()
        if path is None:
            d.load()
        else:
            d.model, d.vocab = load_numpy_artifacts(path)
        detectors[tag] = d
    out = {}
    show = ("deepset_test", "jbb_benign", "jbllms_clean", "safeguard_test", "jackhhao_test", "gandalf_test", "short_benign_heldout", "in_domain_heldout", "own_corpus")
    for name in show:
        items = held[name]
        texts = [t for t, _ in items]; y = np.array([label for _, label in items])
        rb = np.array([rule_based.detect(t).blocked for t in texts])
        em = np.array([emb.detect(t).blocked for t in texts])
        cl = {tag: np.array([d.detect(t).blocked for t in texts]) for tag, d in detectors.items()}
        layers = {"rule_based": rb, "embedding_tfidf": em, "classifier_v1": cl["classifier_v1"], "classifier_shipped": cl["classifier_shipped"],
                  "ensemble_v1": rb | em | cl["classifier_v1"], "ensemble_shipped": rb | em | cl["classifier_shipped"]}
        out[name] = {}
        for lname, flags in layers.items():
            r = {}
            for kind, mask in (("detection", y == 1), ("fpr", y == 0)):
                if mask.any():
                    k, n = int(flags[mask].sum()), int(mask.sum())
                    r[kind] = {"k": k, "n": n, "rate": round(k / n, 3), "ci95": wilson(k, n)}
            out[name][lname] = r
        print(f"\n{name}")
        for lname in layers:
            r = out[name][lname]
            cells = "  ".join(f"{k}={v['k']}/{v['n']} ({v['rate']:.1%}) CI[{v['ci95'][0]:.2f},{v['ci95'][1]:.2f}]" for k, v in r.items())
            print(f"  {lname:<19} {cells}")
    (REPO_ROOT / "reports/p3_shipped_heldout.json").write_text(json.dumps(out, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
