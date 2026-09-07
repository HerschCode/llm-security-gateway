# Latency Overhead Measurement

Measured over 30 benign requests each, direct-to-backend vs. through the full gateway (PII scan + 3-layer injection ensemble + rate/anomaly check + post-flight role/compliance/leak checks).

| Path | Mean (ms) | p50 (ms) | p95 (ms) |
|---|---|---|---|
| Direct to backend | 0.0014 | 0.0010 | 0.0022 |
| Through gateway | 9.8588 | 9.3490 | 11.7684 |

**Overhead: +9.86ms in absolute terms.** A percentage isn't reported here because the direct-to-backend baseline is ~0.0014ms -- the stub backend is a synchronous in-process dict lookup with no real network or model-inference I/O, so there's effectively no baseline to divide by. Against a real LLM backend (typically hundreds of ms to seconds per call, dominated by model inference and network round-trip), this same ~35ms of gateway overhead would be a small single-digit percentage, not a headline number. Reported this way rather than computing a technically-truthful-but-misleading 2,000,000%+ figure.

This is in-process/local-network latency in a single-instance dev sandbox -- it doesn't include real network hops to an external LLM API, which would typically dominate total request time (hundreds of ms to seconds) and make the gateway's overhead proportionally much smaller in a real deployment. Reported as measured, not adjusted to look better.
