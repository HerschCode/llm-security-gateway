# Reproducing the results

> Moved out of the README in Phase 7. Written incrementally during the build: numbers and status here may be older than the README, whose headline tables are generated from the current result files (`scripts/render_readme_headline.py`). Kept because the reasoning and the corrections are the point.

## Running it yourself

**Fastest:** `docker compose up --build`, then open
[http://localhost:8000/gateway/demo](http://localhost:8000/gateway/demo) — an
interactive page that runs the same prompt bypassed vs. through the gateway,
side by side. Full deploy options (Render free tier, the end-to-end trilogy with
the real Project 2) are in [`DEPLOY.md`](../DEPLOY.md).

**Full mode everywhere, including the 512MB free tier:** layer 3 (the scratch
classifier) is served by a torch-free numpy re-implementation of the trained
model's forward pass (`gateway/detectors/classifier_numpy.py`, bit-parity
verified against the original torch model in
`tests/test_classifier_numpy_parity.py`). torch is only used to *train* that
model, not to serve it. `GATEWAY_LITE=1` is kept as an opt-in smaller ensemble
(rule-based + embedding only) if you want one, but it's no longer required for
resource reasons on any of the run modes above.

The service itself is stateless per-request (session/rate-limit state lives in
in-process trackers, not a shared external store — see the note on running
multiple instances under [Known limitations](project-notes.md#known-limitations-stated-plainly-not-buried)),
so the same `Dockerfile` this project already builds runs unmodified as a
Kubernetes `Deployment` behind a `Service` — no orchestrator-specific code
required. No k8s manifests are checked in here since there's no cluster to
demonstrate them against honestly; the point being made is container
portability, not a claim of a tested k8s deployment.

**From source:**

```bash
pip install -r requirements.txt   # Python 3.12 recommended (see DEPLOY.md)
# or: pip install -e ".[dev]"

# 1. Build training data (pulls verazuo/jailbreak_llms from GitHub; needs network)
python scripts/prepare_training_data.py

# 2. Fit/train the detectors
python scripts/fit_embedding_detector.py
python scripts/train_scratch_classifier.py

# 3. Evaluate all three layers against the corpus
python scripts/evaluate.py

# 4. Start the gateway
uvicorn gateway.app:app --port 8000

# 5. In another terminal: attack simulation (through the gateway, or bypassed for comparison)
python scripts/run_redteam.py --target http://localhost:8000 --backend stub_ops_agent
python scripts/run_redteam.py --bypass-gateway

# 6. Latency measurement (gateway must be running)
python scripts/measure_latency.py

# 7. CLI report view (category-level breakdown + gateway on/off comparison)
python scripts/report_cli.py

# 8. Tests
pytest tests/ -v
```

---
