"""
Attack simulation / red-team mode: replays corpus/injection_cases.yaml against
a live target (the gateway's own /gateway/chat endpoint, or -- for comparison
-- a backend hit directly, bypassing the gateway entirely) and produces a
scored pass/fail report per case.

This is the "small pentesting tool" deliverable, run end-to-end against a real
running service (see Proof requirement: "attack simulation report run against
at least one real backend end-to-end"), not just detector functions called
in-process like scripts/evaluate.py does.

Usage:
  python scripts/run_redteam.py --target http://localhost:8000 --backend stub_ops_agent
  python scripts/run_redteam.py --target http://localhost:8000 --backend stub_ops_agent --bypass-gateway
"""
import argparse
import csv
import sys
import time
from pathlib import Path

import httpx
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "corpus" / "injection_cases.yaml"
REPORT_PATH = REPO_ROOT / "docs" / "redteam_report.md"


def load_cases():
    with open(CORPUS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def call_gateway(base_url: str, prompt: str, session_id: str, backend: str, role: str = "employee"):
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{base_url}/gateway/chat", json={
            "prompt": prompt, "session_id": session_id, "role": role, "backend": backend,
        })
        resp.raise_for_status()
        return resp.json()


BACKEND_REGISTRY = {
    "stub_ops_agent": "gateway.adapters.stub_ops_agent:StubOpsAgentAdapter",
    "project2_agent": "gateway.adapters.project2_agent_adapter:Project2AgentAdapter",
    "trivial_echo": "gateway.adapters.trivial_echo:TrivialEchoAdapter",
}


def call_backend_directly(prompt: str, backend_key: str):
    """Bypasses the gateway entirely -- imports the requested backend
    in-process and calls it directly, to demonstrate what happens WITHOUT
    the gateway in front of it. This is the comparison that makes the
    gateway's value observable rather than asserted."""
    sys.path.insert(0, str(REPO_ROOT))
    module_path, class_name = BACKEND_REGISTRY[backend_key].split(":")
    module = __import__(module_path, fromlist=[class_name])
    backend_cls = getattr(module, class_name)
    backend = backend_cls()
    return backend.send(prompt, session_id="redteam-direct", role="employee")


def main():
    parser = argparse.ArgumentParser(description="Replay the attack corpus against a live target.")
    parser.add_argument("--target", default="http://localhost:8000", help="Gateway base URL")
    parser.add_argument("--backend", default="stub_ops_agent", help="Backend key to route through")
    parser.add_argument("--bypass-gateway", action="store_true",
                         help="Call the backend directly, skipping the gateway (for before/after comparison)")
    args = parser.parse_args()

    cases = load_cases()
    results = []

    for case in cases:
        start = time.perf_counter()
        try:
            if args.bypass_gateway:
                response_text = call_backend_directly(case["payload"], args.backend)
                # "Direct" mode has no block concept -- backend always responds.
                allowed = True
                block_reason = None
            else:
                resp = call_gateway(args.target, case["payload"], session_id=f"redteam-{case['id']}", backend=args.backend)
                allowed = resp["allowed"]
                block_reason = resp.get("block_reason")
                response_text = resp.get("response")
        except httpx.ConnectError:
            print(f"ERROR: could not connect to {args.target} -- is the gateway running?")
            print(f"Start it with: uvicorn gateway.app:app --port 8000")
            sys.exit(1)

        latency_ms = (time.perf_counter() - start) * 1000

        expected = case["expected_behavior"]
        if expected == "block":
            passed = not allowed
        elif expected == "allow":
            passed = allowed
        else:  # "flag" -- ambiguous case, always "informational", never fails the run
            passed = True

        results.append({
            "id": case["id"], "category": case["category"], "expected": expected,
            "allowed": allowed, "block_reason": block_reason, "passed": passed,
            "latency_ms": latency_ms, "response_snippet": (response_text or "")[:100],
        })

    # --- Report ---
    n_pass = sum(1 for r in results if r["passed"])
    mode = "DIRECT (gateway bypassed)" if args.bypass_gateway else f"THROUGH GATEWAY (backend={args.backend})"

    lines = [f"# Attack Simulation Report — {mode}\n",
             f"{n_pass}/{len(results)} cases passed.\n",
             "| Case | Category | Expected | Allowed? | Block reason | Latency (ms) | Result |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(
            f"| {r['id']} | {r['category']} | {r['expected']} | {r['allowed']} | "
            f"{r['block_reason'] or '-'} | {r['latency_ms']:.1f} | {'PASS' if r['passed'] else 'FAIL'} |"
        )

    report_text = "\n".join(lines)
    print(report_text)

    suffix = f"_direct_{args.backend}" if args.bypass_gateway else f"_gateway_{args.backend}"
    out_path = REPORT_PATH.with_name(REPORT_PATH.stem + suffix + REPORT_PATH.suffix)
    out_path.write_text(report_text + "\n", encoding="utf-8")
    print(f"\nWritten to {out_path}")


if __name__ == "__main__":
    main()
