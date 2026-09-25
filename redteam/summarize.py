"""
Condense raw red-team run output (redteam/runs/, gitignored) into small committed result files under reports/redteam/.

  garak       per-probe counts (prompts, gateway blocks, attack successes) plus at most 20 example prompts that got through per probe;
              the raw report.jsonl files stay local.
  promptfoo   per-provider and per-category pass counts, and the gateway's block rate per category.
  adaptive    the full attempt log (payloads, victim calls, firewall decisions): it is the evidence for the adaptive findings.
  mutation    every mutated call and the firewall's decision (deterministic, no LLM).

Run: python redteam/summarize.py
"""
import collections
import json
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUNS = REPO / "redteam" / "runs"
OUT = REPO / "reports" / "redteam"


def garak():
    for f in sorted((RUNS / "garak").glob("*.summary.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        for p in d["probes"].values():
            p["through"] = p["through"][:20]
        (OUT / f"garak-{d['tag']}.json").write_text(json.dumps(d, indent=2), encoding="utf-8")
        print("garak", d["tag"], d["totals"])


def promptfoo():
    f = RUNS / "promptfoo.json"
    if not f.exists():
        return
    rows = json.loads(f.read_text(encoding="utf-8"))["results"]["results"]
    per_provider = collections.defaultdict(collections.Counter)
    gateway_blocks = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        prov = r["provider"]["label"]
        cat = (r.get("testCase", {}).get("metadata") or {}).get("category")
        per_provider[prov]["pass" if r.get("success") else "fail"] += 1
        if prov.startswith("gateway"):
            out = (r.get("response") or {}).get("output", "")
            gateway_blocks[cat][1] += 1
            gateway_blocks[cat][0] += out.startswith("[BLOCKED by gateway")
    summary = {"tool": "promptfoo 0.119.0 (eval mode, static hand-written suite)", "per_provider": {k: dict(v) for k, v in per_provider.items()},
               "gateway_blocks_by_category": {k: {"blocked": v[0], "n": v[1]} for k, v in gateway_blocks.items()}}
    (OUT / "promptfoo-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("promptfoo", summary["per_provider"])


def adaptive():
    for f in sorted(RUNS.glob("adaptive-*.json")):
        shutil.copy(f, OUT / f.name)
        d = json.loads(f.read_text(encoding="utf-8"))
        print("adaptive", f.name, d.get("victim"), [(r["goal"], r["text_layers_alone_success"], r["firewall_success"]) for r in d["results"]])


def mutation():
    f = RUNS / "mutation.json"
    if f.exists():
        shutil.copy(f, OUT / "mutation.json")
        print("mutation", json.loads(f.read_text(encoding="utf-8"))["summary"])


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    garak()
    promptfoo()
    adaptive()
    mutation()
