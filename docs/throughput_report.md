# End-to-end throughput and latency: measured, including a real bottleneck found

`scripts/measure_throughput.py` hits a **live** gateway (real `uvicorn`, real
HTTP, not an in-process call — the same standard the redteam reports already
hold themselves to) with a 66-payload mix of benign in-domain queries and
attack cases, at concurrency 1/10/50, 200 requests per level.

Machine: 20 logical cores, CPU only. Full ensemble (`GATEWAY_LITE=0`), backend
`stub_ops_agent` (in-process, no network dependency, so the numbers measure
the gateway's own detection cost, not a downstream LLM call's latency).

## Result: single worker (`uvicorn gateway.app:app`, the default)

| Concurrency | req/s | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| 1 | 26.3 | 38.7ms | 45.8ms | 85.2ms | 297.6ms |
| 10 | 21.1 | 405.0ms | 762.8ms | 1012.4ms | 1068.9ms |
| 50 | 22.5 | 1948.7ms | 2656.0ms | 2966.4ms | 2978.2ms |

**This does not scale with concurrency — it's the opposite of what you'd want.**
req/s is flat-to-declining as concurrency rises, and p50 latency grows almost
exactly linearly with the concurrency level (1x → 10x → 50x concurrency gives
roughly 1x → 10x → 50x the p50 latency). That's the signature of requests
being **serialized**, not actually run in parallel.

## Why: found, not guessed

`/gateway/chat` is a synchronous `def` route (`gateway/app.py`) — FastAPI runs
those in a thread pool, so 50 concurrent requests really do get 50 (pooled)
threads. But the actual work inside `GatewayMiddleware.process()` — TF-IDF
cosine similarity, the numpy classifier's matrix multiplies — is CPU-bound
Python/numpy code. Python's GIL means CPU-bound work across threads doesn't
run in parallel; it takes turns, with thread-switching overhead on top. More
"concurrent" requests just means more threads waiting their turn for the same
GIL, which is exactly the near-linear latency-vs-concurrency scaling observed
above.

## Verified the diagnosis, not just asserted it

Re-ran the identical benchmark with `uvicorn --workers 4` (4 separate
processes — separate GILs, real parallelism across them):

| Concurrency | req/s | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| 1 | 23.4 | 44.4ms | 48.2ms | 53.6ms | 371.8ms |
| 10 | 39.6 | 205.5ms | 475.1ms | 530.8ms | 543.7ms |
| 50 | 47.2 | 924.1ms | 1339.1ms | 1429.9ms | 1435.0ms |

Throughput roughly **doubled** at concurrency 50 (22.5 → 47.2 req/s) and p50
latency roughly **halved** (1948.7ms → 924.1ms) — consistent with the GIL
diagnosis (4 processes ≈ up to 4x the CPU-bound work multiple requests can do
truly simultaneously). It's *not* a clean 4x, though — even 4 independent
processes don't reach 4x throughput at high concurrency, which means there's a
second, smaller bottleneck beyond the GIL (plausibly: OS thread-pool
scheduling overhead inside each worker, or contention writing to the shared
`logs/gateway.jsonl` audit file across processes — not isolated further here).

## What this means, stated plainly

- **At low concurrency (≈1-10 concurrent callers), the gateway is fast**: p50
  under 50ms single-worker, well under what any real LLM call's own latency
  would add on top.
- **The default single-worker process does not handle real concurrent load
  well.** A portfolio demo (one visitor at a time) never hits this; a
  production deployment fronting real traffic would need `--workers N` (N ≈
  CPU count) at minimum, and ideally the CPU-bound detection work moved off
  the request-handling thread pool entirely (a `ProcessPoolExecutor`, or a
  separate detection service called over the network) for true horizontal
  scaling.
- **This is a real, previously-undocumented limitation, found by actually
  measuring instead of assuming FastAPI's "it's async" story meant this was
  fine.** The GIL bottleneck remains; the logging fix below addressed the
  secondary contention.

## Follow-up: logging contention fixed

The multi-worker result hinted at a secondary bottleneck beyond the GIL:
`GatewayLogger.log()` was calling `open(path, "a")` on every single request,
forcing each thread to acquire an OS file lock, write, and release it. Under
concurrent load (even single-worker with many threads waiting for the GIL),
those open/close calls serialized on the filesystem.

Fixed in `gateway/logging_schema.py`: replaced the per-request `open()` with a
**queue-backed background writer thread**. The hot path now does one
`queue.put()` (≈1 µs, no file I/O); a daemon thread drains the queue in
batches and flushes once per batch.

Re-ran the single-worker benchmark after the fix:

| Concurrency | req/s | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| 1 | 31.7 | 32.7ms | 49.6ms | 77.7ms | 283.4ms |
| 10 | 36.6 | 289.0ms | 510.0ms | 778.3ms | 790.8ms |
| 50 | 31.2 | 1643.0ms | 1923.5ms | 2041.3ms | 2141.1ms |

vs. before (same single-worker, same machine):

| Concurrency | req/s | p50 | Δ req/s |
|---|---|---|---|
| 1 | 26.3 | 38.7ms | +20% |
| 10 | 21.1 | 405.0ms | **+73%** |
| 50 | 22.5 | 1948.7ms | +39% |

The improvement is largest at c=10 — exactly where multiple threads were
contending most heavily on the file handle. At c=50 the GIL still dominates;
at c=1 the file I/O was a small fraction of total request time. The GIL
ceiling remains, but the audit log no longer adds to it.

## Reproducing this

```bash
uvicorn gateway.app:app --port 8000 &            # or: --workers 4
python scripts/measure_throughput.py --url http://localhost:8000
```

Raw data: [`throughput_raw_result.json`](throughput_raw_result.json) (single-worker run).
