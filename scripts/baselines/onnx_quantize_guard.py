"""
Phase 2, step 2: can the guard model be made small and fast enough to serve, via ONNX Runtime + int8?

Exports protectai/deberta-v3-base-prompt-injection-v2 to ONNX, then measures three variants
against the fp32 PyTorch model on the standard held-out sets:
  fp32-ort            ONNX fp32 (isolates the runtime change from quantization)
  int8-matmul         dynamic int8 on MatMul weights only (encoder), embeddings stay fp32
  int8-matmul+gather  dynamic int8 on MatMul and Gather (also quantizes the 128k-token embedding
                      table, which is ~half of DeBERTa-v3-base's parameters)

Per variant: file size, incremental process RSS (measured in a fresh child process so it is not
polluted by torch), single-example p50 latency on CPU, decision agreement with fp32 torch, max
probability difference, and detection / FPR / ROC-AUC per held-out set. A variant that breaks the
model is reported as broken; nothing is hidden.

The serving-relevant runtime here is onnxruntime + the `tokenizers` package (no torch, no
transformers), matching this project's torch-free serving constraint.

Run: python -X utf8 -m scripts.baselines.onnx_quantize_guard
Writes reports/p3_onnx_quantization.json; ONNX files go to data/external/onnx_guard/ (gitignored).
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import roc_auc_score

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.baselines.run_guard_baselines import MODELS, SETS, load_guard, set_metrics  # noqa: E402
from scripts.retrain_classifier_v2 import load_sources  # noqa: E402

MODEL_DIR = MODELS[0]["local_dir"]
OUT_DIR = REPO_ROOT / "data/external/onnx_guard"
MAX_LEN = 512
LATENCY_SAMPLE = 120


def export_fp32(model, tok, path: Path):
    enc = tok(["export example text"], return_tensors="pt")
    model.config.return_dict = True
    torch.onnx.export(
        model, (enc["input_ids"], enc["attention_mask"]), str(path),
        input_names=["input_ids", "attention_mask"], output_names=["logits"],
        dynamic_axes={"input_ids": {0: "b", 1: "s"}, "attention_mask": {0: "b", 1: "s"}, "logits": {0: "b"}},
        opset_version=17, do_constant_folding=True, dynamo=False,
    )


def quantize(src: Path, dst: Path, op_types, per_channel=False, exclude=None):
    from onnxruntime.quantization import QuantType, quantize_dynamic
    quantize_dynamic(str(src), str(dst), weight_type=QuantType.QInt8, op_types_to_quantize=op_types,
                     per_channel=per_channel, nodes_to_exclude=exclude or [])


def attention_matmuls(src: Path):
    """MatMul nodes in the attention blocks (q/k/v/position projections and the attention output
    dense). Excluding them leaves only the feed-forward layers quantized."""
    import onnx
    m = onnx.load(str(src), load_external_data=False)
    return [n.name for n in m.graph.node if n.op_type == "MatMul" and "/attention/" in n.name]


class OrtGuard:
    def __init__(self, path: Path, injection_idx: int):
        import onnxruntime as ort
        from tokenizers import Tokenizer
        so = ort.SessionOptions()
        so.intra_op_num_threads = 4
        self.sess = ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])
        self.tok = Tokenizer.from_file(str(MODEL_DIR / "tokenizer.json"))
        self.tok.enable_truncation(MAX_LEN)
        self.idx = injection_idx

    def scores(self, texts, batch_size=16):
        out = []
        for i in range(0, len(texts), batch_size):
            encs = self.tok.encode_batch(texts[i:i + batch_size])
            width = max(len(e.ids) for e in encs)
            ids = np.zeros((len(encs), width), dtype=np.int64)
            mask = np.zeros((len(encs), width), dtype=np.int64)
            for j, e in enumerate(encs):
                ids[j, :len(e.ids)] = e.ids
                mask[j, :len(e.ids)] = 1
            logits = self.sess.run(None, {"input_ids": ids, "attention_mask": mask})[0]
            e = np.exp(logits - logits.max(axis=1, keepdims=True))
            out.extend((e / e.sum(axis=1, keepdims=True))[:, self.idx].tolist())
        return np.array(out)


def rss_child(path: Path) -> float:
    """Incremental RSS (MB) of creating an ORT session + one warm inference, in a fresh process."""
    code = (
        "import os, psutil, numpy as np, onnxruntime as ort\n"
        "p = psutil.Process(); r0 = p.memory_info().rss\n"
        f"s = ort.InferenceSession(r'{path}', providers=['CPUExecutionProvider'])\n"
        "ids = np.ones((1, 32), dtype=np.int64)\n"
        "s.run(None, {'input_ids': ids, 'attention_mask': ids})\n"
        "print((p.memory_info().rss - r0) / 2**20)\n"
    )
    return round(float(subprocess.check_output([sys.executable, "-c", code], text=True).strip().splitlines()[-1]), 1)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tok, model, idx, _ = load_guard(MODELS[0])
    _, held = load_sources()
    sets = {k: held[k] for k in SETS}

    fp32_path = OUT_DIR / "guard_fp32.onnx"
    if not fp32_path.exists():
        print("exporting fp32 ONNX ...")
        export_fp32(model, tok, fp32_path)
    ap = argparse.ArgumentParser()
    ap.add_argument("--variants", nargs="*", help="only (re)measure these variants; others are kept from the existing report")
    args = ap.parse_args()
    variants = {"fp32-ort": fp32_path}
    specs = (
        ("int8-matmul", dict(op_types=["MatMul"])),
        ("int8-matmul+gather", dict(op_types=["MatMul", "Gather"])),
        ("int8-perchannel", dict(op_types=["MatMul"], per_channel=True)),
        ("int8-ffn-only-perchannel", dict(op_types=["MatMul"], per_channel=True, exclude="attention")),
    )
    for name, kw in specs:
        if args.variants and name not in args.variants:
            continue
        dst = OUT_DIR / f"guard_{name.replace('+', '_')}.onnx"
        if not dst.exists():
            print(f"quantizing {name} ...")
            try:
                if kw.get("exclude") == "attention":
                    kw = {**kw, "exclude": attention_matmuls(fp32_path)}
                quantize(fp32_path, dst, **kw)
            except Exception as exc:  # noqa: BLE001 -- report a failed variant, do not hide it
                variants[name] = ("FAILED", f"{type(exc).__name__}: {str(exc)[:200]}")
                continue
        variants[name] = dst

    pool = [t for k in SETS for t, _ in sets[k]]
    rng = np.random.default_rng(0)
    sample = [pool[i] for i in rng.choice(len(pool), LATENCY_SAMPLE, replace=False)]

    def torch_scores(texts, bs=16):
        out = []
        with torch.no_grad():
            for i in range(0, len(texts), bs):
                enc = tok(texts[i:i + bs], return_tensors="pt", truncation=True, padding=True, max_length=MAX_LEN)
                out.extend(torch.softmax(model(**enc).logits, dim=-1)[:, idx].numpy().tolist())
        return np.array(out)

    ref = {k: torch_scores([t for t, _ in v]) for k, v in sets.items()}
    lat_ref = []
    for t in sample:
        t0 = time.perf_counter(); torch_scores([t], 1); lat_ref.append((time.perf_counter() - t0) * 1000)

    report_path = REPO_ROOT / "reports/p3_onnx_quantization.json"
    previous = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() and args.variants else {"variants": {}}
    results = {"reference_torch_fp32": {"p50_latency_ms": round(float(np.median(lat_ref)), 1), "size_mb": round((MODEL_DIR / "model.safetensors").stat().st_size / 2**20, 1),
                                        "results": {k: set_metrics(ref[k] >= 0.5, np.array([label for _, label in sets[k]]), ref[k]) for k in sets}},
               "variants": dict(previous.get("variants", {}))}
    for name, path in variants.items():
        if isinstance(path, tuple):
            results["variants"][name] = {"status": "failed", "reason": path[1]}
            print(f"{name}: FAILED {path[1]}")
            continue
        g = OrtGuard(path, idx)
        lat = []
        for t in sample:
            t0 = time.perf_counter(); g.scores([t], 1); lat.append((time.perf_counter() - t0) * 1000)
        entry = {"status": "ok", "size_mb": round(path.stat().st_size / 2**20, 1), "rss_delta_mb": rss_child(path),
                 "p50_latency_ms": round(float(np.median(lat)), 1), "results": {}, "vs_fp32_torch": {}}
        for k, items in sets.items():
            y = np.array([label for _, label in items])
            s = g.scores([t for t, _ in items])
            entry["results"][k] = set_metrics(s >= 0.5, y, s)
            entry["vs_fp32_torch"][k] = {"decision_agreement": round(float(((s >= 0.5) == (ref[k] >= 0.5)).mean()), 4),
                                         "max_abs_prob_diff": round(float(np.abs(s - ref[k]).max()), 4)}
        results["variants"][name] = entry
        print(f"{name}: {entry['size_mb']} MB, +{entry['rss_delta_mb']} MB RSS, p50 {entry['p50_latency_ms']} ms; "
              f"agreement {[v['decision_agreement'] for v in entry['vs_fp32_torch'].values()]}")

    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n(detection/FPR by set)")
    def cell(m):
        det = f"{m['detection']['rate']:.0%}" if "detection" in m else "-"
        fpr = f"{m['fpr']['rate']:.0%}" if "fpr" in m else "-"
        return f"{det}/{fpr}"
    print(f"{'variant':<22}" + "".join(f"{s[:13]:<15}" for s in SETS))
    print(f"{'torch fp32':<22}" + "".join(f"{cell(results['reference_torch_fp32']['results'][s]):<15}" for s in SETS))
    for name, e in results["variants"].items():
        if e.get("status") == "ok":
            print(f"{name:<22}" + "".join(f"{cell(e['results'][s]):<15}" for s in SETS))
    print("\nWrote reports/p3_onnx_quantization.json")


if __name__ == "__main__":
    main()
