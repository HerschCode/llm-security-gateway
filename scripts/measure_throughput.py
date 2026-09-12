"""
End-to-end throughput/latency benchmark against a LIVE gateway process (real
HTTP, real FastAPI/uvicorn worker, not an in-process function call -- the same
"live server, not a shortcut" standard the redteam reports already hold
themselves to).

Usage:
    uvicorn gateway.app:app --port 8000 &
    python scripts/measure_throughput.py --url http://localhost:8000

Reports p50/p95/p99 latency and requests/sec at several concurrency levels,
against a realistic mix of benign and attack payloads (not just one repeated
request, which would flatter cache-friendly paths that don't exist here but
would be a lazy benchmark regardless).
"""
import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

import httpx
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONCURRENCY_LEVELS = [1, 10, 50]
REQUESTS_PER_LEVEL = 200


def load_mixed_payloads() -> list[str]:
    """A realistic mix: benign in-domain queries + attack payloads from the
    corpus, not a single repeated string -- a gateway's real traffic is never
    one message hammered forever, and pre-flight short-circuits on a rule-based
    hit, so an all-attack benchmark would understate latency for the requests
    that actually reach layers 2/3."""
    payloads = []
    with open(REPO_ROOT / "corpus" / "benign_indomain_queries.yaml", encoding="utf-8") as f:
        for c in yaml.safe_load(f):
            payloads.append(c["text"])
    with open(REPO_ROOT / "corpus" / "injection_cases.yaml", encoding="utf-8") as f:
        for c in yaml.safe_load(f):
            payloads.append(c["payload"])
    return payloads


async def _one_request(client: httpx.AsyncClient, url: str, prompt: str, session_id: str) -> float:
    t0 = time.perf_counter()
    await client.post(f"{url}/gateway/chat", json={
        "prompt": prompt, "session_id": session_id, "backend": "stub_ops_agent",
    })
    return (time.perf_counter() - t0) * 1000


async def run_level(url: str, concurrency: int, n_requests: int, payloads: list[str]) -> dict:
    latencies = []
    sem = asyncio.Semaphore(concurrency)

    async def bound(i, client):
        async with sem:
            prompt = payloads[i % len(payloads)]
            # Unique session per request -- otherwise the per-session rate
            # limiter (gateway/session_checks.py) starts blocking requests
            # partway through the benchmark, which would measure the rate
            # limiter's reject path, not the detection pipeline's real cost.
            lat = await _one_request(client, url, prompt, session_id=f"bench-{concurrency}-{i}")
            latencies.append(lat)

    async with httpx.AsyncClient(timeout=30) as client:
        t0 = time.perf_counter()
        await asyncio.gather(*(bound(i, client) for i in range(n_requests)))
        wall_s = time.perf_counter() - t0

    latencies.sort()
    def pctl(p): return latencies[min(int(len(latencies) * p), len(latencies) - 1)]

    return {
        "concurrency": concurrency,
        "n_requests": n_requests,
        "wall_seconds": round(wall_s, 3),
        "req_per_sec": round(n_requests / wall_s, 2),
        "p50_ms": round(pctl(0.50), 2),
        "p95_ms": round(pctl(0.95), 2),
        "p99_ms": round(pctl(0.99), 2),
        "max_ms": round(max(latencies), 2),
    }


async def main_async(url: str):
    payloads = load_mixed_payloads()
    print(f"Benchmarking {url} with a {len(payloads)}-payload mix "
          f"({sum(1 for _ in payloads)} total: benign + attack)\n")

    # Warm up (first request after cold start / lazy model load shouldn't
    # pollute the measured latencies).
    async with httpx.AsyncClient(timeout=30) as client:
        await client.get(f"{url}/health")
        await _one_request(client, url, payloads[0], "warmup")

    results = []
    for c in CONCURRENCY_LEVELS:
        r = await run_level(url, c, REQUESTS_PER_LEVEL, payloads)
        results.append(r)
        print(f"concurrency={c:>3}  {r['req_per_sec']:>7.1f} req/s  "
              f"p50={r['p50_ms']:>7.2f}ms  p95={r['p95_ms']:>7.2f}ms  "
              f"p99={r['p99_ms']:>7.2f}ms  max={r['max_ms']:>7.2f}ms")

    out_path = REPO_ROOT / "docs" / "throughput_raw_result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nRaw result written to {out_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    args = parser.parse_args()
    asyncio.run(main_async(args.url))


if __name__ == "__main__":
    main()
