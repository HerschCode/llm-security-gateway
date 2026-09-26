"""
Llama Prompt Guard 2 (22M and 86M) scored through Groq's hosted inference (free tier), on the project's held-out sets.

Why this exists: the Meta repos are gated on Hugging Face and no HF_TOKEN was available, so `run_guard_baselines.py` records them as
not_evaluated. Groq serves both models (`meta-llama/llama-prompt-guard-2-22m` / `-86m`) and the free tier is enough for the ~625 held-out
texts, so the ACCURACY comparison does not have to wait. What this cannot give: memory, local CPU latency and an ONNX/int8 build (those
need the weights) and it is only as faithful as Groq's deployment of the same checkpoints (a parity check against the local weights is
listed in docs/guard-baselines.md as still to do).

Protocol, matched to the local ProtectAI run: threshold 0.5, the same six held-out sets (5 ambiguous own-corpus "flag" cases excluded),
inputs cut to their first 1,500 characters (about 350-400 tokens; the local protocol keeps the first 512 tokens). The hosted API rejects inputs over
512 tokens, so the cut is by characters and is shortened further only if the API still rejects it. 134 of the 625 texts are affected, nearly all of them
jailbreak_llms prompts. Meta recommends splitting long inputs into segments and taking the max, which would score higher on those and is not done here.

Configurations scored on the same texts: each guard alone; rules OR guard (the candidate new default: the guard replaces the numpy
classifier); rules OR classifier OR guard; and the shipped default (rules OR numpy classifier, TF-IDF layer off since Phase 2).

Run:  GROQ_API_KEY=... python -X utf8 -m scripts.baselines.run_guard_hosted      -> reports/p3_guard_hosted.json
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import httpx
import numpy as np
from sklearn.metrics import roc_auc_score

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from gateway.detectors import rule_based  # noqa: E402
from gateway.detectors.classifier_numpy import ScratchClassifierDetectorNumpy  # noqa: E402
from scripts.baselines.run_guard_baselines import LABEL_CHECK_EXAMPLES, SETS, set_metrics  # noqa: E402
from scripts.retrain_classifier_v2 import load_sources  # noqa: E402

URL = "https://api.groq.com/openai/v1/chat/completions"
MODELS = {"Llama-Prompt-Guard-2-22M": "meta-llama/llama-prompt-guard-2-22m", "Llama-Prompt-Guard-2-86M": "meta-llama/llama-prompt-guard-2-86m"}
CACHE_DIR = REPO_ROOT / "data" / "external" / "pg2_groq_cache"
TPM_BUDGET = 13_000          # the free tier allows 15,000 input tokens per minute
RPM_BUDGET = 28              # ... and 30 requests per minute (the binding limit for these short texts: ~2 minutes per 55 texts)
START_CHARS = 1500


class Hosted:
    def __init__(self, name: str, model: str, key: str):
        self.name, self.model, self.key = name, model, key
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.cache_path = CACHE_DIR / f"{name}.json"
        self.cache = json.loads(self.cache_path.read_text(encoding="utf-8")) if self.cache_path.exists() else {}
        self.window: list[tuple[float, int]] = []
        self.requests = self.truncated = 0

    def _pace(self, tokens: int):
        while True:
            now = time.time()
            self.window = [(t, n) for t, n in self.window if now - t < 60]
            if sum(n for _, n in self.window) + tokens <= TPM_BUDGET and len(self.window) < RPM_BUDGET:
                self.window.append((now, tokens))
                return
            time.sleep(max(0.5, 60 - (now - self.window[0][0]) + 0.2))

    def score(self, text: str) -> float:
        """P(malicious) for the first START_CHARS characters of `text`."""
        k = hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()   # a cache key, not a security use  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 - cache key only, usedforsecurity=False
        if k in self.cache:
            return self.cache[k]
        chars = min(len(text), START_CHARS)
        for _ in range(40):
            piece = text[:chars]
            self._pace(len(piece) // 3 + 20)
            try:
                r = httpx.post(URL, headers={"Authorization": f"Bearer {self.key}"}, timeout=60,
                               json={"model": self.model, "messages": [{"role": "user", "content": piece}]})
            except httpx.TransportError:                      # dropped connection / timeout: keep what is cached and try again
                self.save()
                time.sleep(5)
                continue
            self.requests += 1
            if r.status_code == 200:
                s = float(r.json()["choices"][0]["message"]["content"])
                self.truncated += len(piece) < len(text)
                self.cache[k] = s
                if self.requests % 40 == 0:
                    self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")
                return s
            if r.status_code == 400 and "reduce the length" in r.text:
                chars = int(chars * 0.7)
                continue
            if r.status_code == 429:
                time.sleep(float(r.headers.get("retry-after", "5")) + 0.5)
                continue
            raise RuntimeError(f"{self.model}: HTTP {r.status_code} {r.text[:160]}")
        raise RuntimeError(f"{self.model}: could not fit input under the context limit")

    def save(self):
        self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")


def label_check(h: Hosted) -> dict:
    """Which reading of the returned number means "attack"? Counts correct calls on 10 hand-labelled examples for the score as
    P(malicious) and for its complement. Numbers are only trusted if one reading gets >= 9/10 and the other <= 2/10."""
    scores = [h.score(t) for t, _ in LABEL_CHECK_EXAMPLES]
    truth = [y for _, y in LABEL_CHECK_EXAMPLES]
    as_malicious = sum(int(s >= 0.5) == y for s, y in zip(scores, truth))
    as_benign = sum(int(s < 0.5) == y for s, y in zip(scores, truth))
    return {"score_is_p_malicious_correct": as_malicious, "complement_correct": as_benign, "n": len(truth),
            "verified": as_malicious >= 9 and as_benign <= 2, "scores": [round(s, 4) for s in scores]}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=list(MODELS), choices=list(MODELS),
                    help="rate limits are per model, so two processes can fill the two caches in parallel")
    ap.add_argument("--out", default=str(REPO_ROOT / "reports" / "p3_guard_hosted.json"))
    args = ap.parse_args()
    key = os.environ["GROQ_API_KEY"]
    _, held = load_sources()
    sets = {k: held[k] for k in SETS}
    clf = ScratchClassifierDetectorNumpy()
    clf.load()

    texts = {n: [t for t, _ in items] for n, items in sets.items()}
    y = {n: np.array([lab for _, lab in items]) for n, items in sets.items()}
    rules = {n: np.array([bool(rule_based.detect(t).blocked) for t in texts[n]]) for n in sets}
    cls = {n: np.array([bool(clf.detect(t).blocked) for t in texts[n]]) for n in sets}
    cls_prob = {n: np.array([clf.detect(t).confidence for t in texts[n]]) for n in sets}
    shipped = {n: rules[n] | cls[n] for n in sets}

    out = {"threshold": 0.5, "source": "Groq-hosted inference, free tier; inputs cut to the first 1,500 characters; see module docstring",
           "sets": {n: {"n": len(texts[n]), "attacks": int(y[n].sum())} for n in sets},
           "shipped_default": {"description": "rules OR numpy classifier (TF-IDF layer off)", "results": {n: set_metrics(shipped[n], y[n]) for n in sets}},
           "rules_alone": {n: set_metrics(rules[n], y[n]) for n in sets},
           "classifier_alone": {n: set_metrics(cls[n], y[n]) for n in sets},
           "models": {}}
    for name, model in ((n, m) for n, m in MODELS.items() if n in args.models):
        h = Hosted(name, model, key)
        chk = label_check(h)
        entry = {"hosted_model": model, "label_check": chk}
        if not chk["verified"]:
            entry["status"] = "not_evaluated"
            entry["reason"] = "label reading could not be verified on the 10 hand-labelled examples"
            out["models"][name] = entry
            print(name, "NOT VERIFIED", chk)
            continue
        print(f"{name}: label check {chk['score_is_p_malicious_correct']}/10 (complement {chk['complement_correct']}/10); scoring {sum(len(v) for v in texts.values())} texts")
        scores = {n: np.array([h.score(t) for t in texts[n]]) for n in sets}
        h.save()
        entry.update(status="evaluated", requests_this_run=h.requests,   # 0 when everything came from the score cache
                     inputs_longer_than_first_chunk=sum(len(t) > START_CHARS for v in texts.values() for t in v),
                     alone={n: set_metrics(scores[n] >= 0.5, y[n], scores[n]) for n in sets},
                     rules_or_guard={n: set_metrics(rules[n] | (scores[n] >= 0.5), y[n]) for n in sets},
                     rules_or_classifier_or_guard={n: set_metrics(shipped[n] | (scores[n] >= 0.5), y[n]) for n in sets})
        # Operating-point-matched comparison. Chosen on the evaluation sets themselves, so optimistic for the guard; used for the decision only.
        #   guard_alone     the guard's threshold is the lowest one whose false positives on the pooled benign texts do not exceed the shipped default's
        #   rules_or_guard  the same budget applied to "rules OR guard" (the candidate new default) versus "rules OR classifier" (the shipped default)
        benign_idx = {n: y[n] == 0 for n in sets}
        target_fp = sum(int(shipped[n][benign_idx[n]].sum()) for n in sets)
        pooled_benign = sum(int(benign_idx[n].sum()) for n in sets)
        cands = sorted({float(s) for n in sets for s in scores[n]} | {0.5})

        def lowest_threshold(fp_at):
            for t in cands:
                if fp_at(t) <= target_fp:
                    return t
            return 1.0 + 1e-9

        t_alone = lowest_threshold(lambda t: sum(int((scores[n][benign_idx[n]] >= t).sum()) for n in sets))
        t_rules = lowest_threshold(lambda t: sum(int((rules[n] | (scores[n] >= t))[benign_idx[n]].sum()) for n in sets))
        entry["fpr_matched"] = {
            "pooled_benign": pooled_benign, "shipped_default_false_positives": target_fp,
            "guard_alone": {"threshold": round(t_alone, 6),
                            "false_positives": sum(int((scores[n][benign_idx[n]] >= t_alone).sum()) for n in sets),
                            "results": {n: set_metrics(scores[n] >= t_alone, y[n], scores[n]) for n in sets}},
            "rules_or_guard": {"threshold": round(t_rules, 6),
                               "false_positives": sum(int((rules[n] | (scores[n] >= t_rules))[benign_idx[n]].sum()) for n in sets),
                               "results": {n: set_metrics(rules[n] | (scores[n] >= t_rules), y[n]) for n in sets}}}
        entry["scores"] = {n: [round(float(s), 5) for s in scores[n]] for n in sets}
        out["models"][name] = entry
    out["classifier_layer_roc_auc"] = {n: round(float(roc_auc_score(y[n], cls_prob[n])), 3) for n in ("own_corpus", "deepset_test")}
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")

    def cell(m, kind):
        r = m.get(kind)
        return f"{r['rate']:.1%} ({r['k']}/{r['n']})" if r else "n/a"

    print("\n=== detection | FPR (threshold 0.5) ===")
    cols = [("shipped default", lambda n, e: out["shipped_default"]["results"][n])]
    ev = {k: e for k, e in out["models"].items() if e.get("status") == "evaluated"}
    for k, e in ev.items():
        short = k.split("-")[-1]
        cols += [(f"PG2 {short} alone", lambda n, e=e: e["alone"][n]), (f"rules+PG2 {short}", lambda n, e=e: e["rules_or_guard"][n]),
                 (f"rules+clf+PG2 {short}", lambda n, e=e: e["rules_or_classifier_or_guard"][n])]
    for n in sets:
        print(f"\n{n}")
        for label, f in cols:
            m = f(n, None) if label == "shipped default" else f(n)
            print(f"  {label:<24} detection {cell(m, 'detection'):<16} FPR {cell(m, 'fpr')}")
    for k, e in ev.items():
        fm = e["fpr_matched"]
        print(f"\n{k}: FPR-matched (pooled false-positive budget {fm['shipped_default_false_positives']} of {fm['pooled_benign']} benign, the shipped default's)")
        for label, key in (("guard alone", "guard_alone"), ("rules OR guard", "rules_or_guard")):
            print(f"  {label}: threshold {fm[key]['threshold']}, {fm[key]['false_positives']} false positives")
            for n in ("own_corpus", "deepset_test", "jbllms_clean"):
                print(f"    {n:<16} detection {cell(fm[key]['results'][n], 'detection')}")
        print(f"  ROC-AUC own_corpus {e['alone']['own_corpus'].get('roc_auc')}, deepset {e['alone']['deepset_test'].get('roc_auc')} (classifier layer: {out['classifier_layer_roc_auc']})")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
