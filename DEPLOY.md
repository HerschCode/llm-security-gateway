# Deploying / Running the LLM Security Gateway

Three ways to run it, smallest to largest.

| Setup | Layers | Backends | Needs | Use for |
|---|---|---|---|---|
| **Render free tier** | all 3 (torch-free serving — see below) | stub_ops_agent, project2_agent, operations_assistant | nothing | public link for recruiters |
| **`docker compose up`** | all 3 | stub_ops_agent, project2_agent | Docker | recording the core demo |
| **`docker-compose.trilogy.yml`** | all 3 | + **operations_assistant** (real Project 2) | Docker + free Groq key + the other two repos | "I ran all three connected" demo / video |

---

## 1. Render free tier (public link, zero secrets)

The gateway is a single container. `render.yaml` is a Blueprint that needs no
configuration.

1. Push this repo to GitHub.
2. In the [Render dashboard](https://dashboard.render.com/) → **New +** → **Blueprint**.
3. Select the repo. Render reads `render.yaml` and creates the `llm-security-gateway`
   web service on the **free** plan, building from `Dockerfile.render`.
4. Wait for the first build (~3-5 min). Then:
   - `https://<your-service>.onrender.com/gateway/demo` — interactive demo
   - `https://<your-service>.onrender.com/gateway/dashboard` — live traffic
   - `https://<your-service>.onrender.com/health`

**Free-tier caveats (state these honestly on the portfolio site):**
- **All 3 detection layers run.** Layer 3 used to be dropped on this tier
  (`GATEWAY_LITE=1`) because it was torch-backed and torch didn't fit 512MB.
  It's now served by `gateway/detectors/classifier_numpy.py` — a torch-free
  re-implementation of the same trained model's forward pass, verified
  bit-parity against the original in `tests/test_classifier_numpy_parity.py`.
  torch is still used to *train* that model (`scripts/train_scratch_classifier.py`),
  just not to *serve* it. `GATEWAY_LITE=1` still exists as an opt-in smaller
  ensemble, it's just no longer necessary here — see `docs/decisions.md`.
- Spins down after ~15 min idle; the next request takes ~30-60s to wake.

**No API keys.** `render.yaml` points `OPS_ASSISTANT_URL` at the deployed
operations-assistant and uses its **public, keyless, IP-rate-limited**
`/demo/chat` endpoint (`OPS_ASSISTANT_CHAT_PATH=/demo/chat`) — so the
`operations_assistant` backend works in the live demo without any secret. Remove
those two lines from `render.yaml` to hide that backend instead.

**Known limitation: the rate limit is shared across every visitor, not
per-visitor.** operations-assistant's `/demo/chat` rate-limits by caller IP —
but the caller it sees is always the gateway's own server IP, since the
gateway doesn't forward the original visitor's IP (no `X-Forwarded-For`
passthrough in `gateway/adapters/operations_assistant_adapter.py`). That
means the 5-requests-per-10-minutes quota is one shared pool across *every*
concurrent demo visitor, not 5 per visitor — a burst of visitors can exhaust
it quickly, surfacing as `UPSTREAM ERROR: HTTP 429` on the demo page (a
real error rendered correctly as "not a detection-layer decision," not
silently miscounted as a block). Fixing this properly means forwarding the
real client IP through the adapter and having operations-assistant trust it
specifically from the gateway's known origin — not built here.

Check wiring any time at `…/gateway/connectivity` — it reports, per backend,
whether the gateway can actually reach it.

---

## 2. Full pipeline locally (`docker compose up`)

All three detection layers, no external services.

```bash
docker compose up --build
# open http://localhost:8000/gateway/demo
```

This is the setup to screen-record: pick an attack, watch all three layer
chips, watch the gateway block what the backend alone leaks. (Now identical to
what the Render deploy runs, layer-for-layer — see below.)

---

## 3. The trilogy, end to end (`docker-compose.trilogy.yml`)

```
caller → [ P3: LLM Security Gateway ] → [ P2: operations-assistant ] → [ P1: operations-performance API ]
```

**This is verified working in production, not just locally** — `/gateway/connectivity`
on the live deployment shows `operations_assistant: reachable: true` talking to a real
Groq-backed agent, which itself reaches a real Postgres-backed `operations-performance`
instance. A real question through `/gateway/chat` (backend `operations_assistant`)
returns a genuine cited answer with real data + policy citations, and a genuine attack
prompt is correctly blocked pre-flight before ever reaching P2. Check
`/gateway/connectivity` on the live URL at any time to see current reachability.

**All three services now run in containers** -- `operations-performance` and its own
Postgres are part of `docker-compose.trilogy.yml` too (this used to require Project 1
running separately on the host at `:8000`; that requirement is gone).

### Prerequisites

1. **All three repos** checked out, flat (no nested `operations-x/operations-x`
   folder in either companion repo). If your layout differs from
   `../../0_Project/operations-performance` and `../../0_Project/operations-assistant`
   relative to this repo, set `OPS_PERFORMANCE_PATH` / `OPS_ASSISTANT_PATH` (env vars
   or a `.env` next to this file).
2. **`operations-assistant/.env`** with a free Groq key
   ([console.groq.com](https://console.groq.com/keys)):
   ```
   AGENT_PROVIDER=groq
   AGENT_MODEL=openai/gpt-oss-120b
   GROQ_API_KEY=gsk_...
   ```
   Check [console.groq.com/docs/models](https://console.groq.com/docs/models) or run
   `client.models.list()` for the current lineup rather than trusting a name pinned
   in a doc to stay valid indefinitely -- Groq's models change over time.
   (Gemini works too: `AGENT_PROVIDER=gemini`, `AGENT_MODEL=gemini-1.5-flash`,
   `GEMINI_API_KEY=...` from [aistudio.google.com/apikey](https://aistudio.google.com/apikey).
   Anthropic: `AGENT_PROVIDER=anthropic`, `ANTHROPIC_API_KEY=sk-ant-...`.)
3. **First run only** — bring up Postgres, set up and load Project 1's database,
   then build Project 2's vector index:
   ```bash
   docker compose -f docker-compose.trilogy.yml up -d postgres
   docker compose -f docker-compose.trilogy.yml run --rm operations-performance \
     python -m scripts.setup_database
   docker compose -f docker-compose.trilogy.yml run --rm operations-performance \
     python -m scripts.run_pipeline
   docker compose -f docker-compose.trilogy.yml run --rm operations-assistant \
     python -m scripts.index_documents
   ```

### Run

```bash
docker compose -f docker-compose.trilogy.yml up --build
# open http://localhost:8080/gateway/demo  → pick the "operations_assistant" backend
```

---

## 4. Google Cloud Run, behind Terraform-managed IAM ([northstar-infra](https://github.com/HerschCode/northstar-infra))

The whole trilogy on Cloud Run where **only the gateway is public**: operations-assistant and
operations-performance accept calls only from the service account of the service in front of them,
and Cloud Run IAM answers 403 to everyone else.

- The image is `Dockerfile.render` (the torch-free serving set).
- `AUTH_MODE=google_id_token` makes the operations-assistant adapter send a Google ID token minted for
  `OPS_ASSISTANT_URL` (`Authorization: Bearer ...`) instead of `X-API-Key`, and turns off the
  `/chat` to `/demo/chat` fallback on 401, which would hide a credentials problem behind the anonymous
  route. Tokens are cached and refreshed shortly before they expire. It needs a Google service-account
  identity, so it works on Cloud Run only: leave `AUTH_MODE` unset elsewhere. Code:
  `gateway/adapters/upstream_auth.py`; tests: `tests/test_upstream_auth.py`.
- `.github/workflows/deploy.yml` builds the image, scans it with Trivy, pushes it to Artifact Registry
  and rolls the service over to it. Manual dispatch only, from `main`, and a no-op until the
  repository variables that Terraform prints exist. It has not been run against a real project yet.
- Not done yet: the decision log goes to `logs/gateway.jsonl`, which Cloud Run discards, while the
  block-rate alert in northstar-infra counts `jsonPayload.decision="block"` on stdout. A JSON line on
  stdout is needed for that alert to fire.
- `TRUSTED_PROXY_HOPS` is unset (as on Render), so the per-IP limit treats Google's front end as one
  client until the real `X-Forwarded-For` chain has been verified.

---

## Environment variables (reference)

| Var | Where | Required? | What |
|---|---|---|---|
| `GATEWAY_LITE` | gateway | no (default `0`) | `1` opts into a smaller ensemble (rule-based + embedding only). No longer needed for RAM — layer 3 is served torch-free either way, see `docs/decisions.md` |
| `EMBEDDING_BACKEND` | gateway | no (default `none`) | Layer 2 is **disabled by default** (the TF-IDF layer added nothing on our corpus, see `docs/ensemble-ablation.md`). `tfidf` re-enables it as an ablation; `sentence_transformer` swaps in a real MiniLM embedding (needs `pip install sentence-transformers`, pulls in torch, ~9 ms). Any other value is rejected at startup |
| `PORT` | gateway | no (default `8000`) | Render sets this automatically |
| `OPS_ASSISTANT_URL` | gateway | only for the real-P2 backend | e.g. `http://operations-assistant:8001`; if unset the backend is not registered |
| `OPS_ASSISTANT_CHAT_PATH` | gateway | no (default `/chat`) | set to `/demo/chat` to use P2's keyless public endpoint instead of the API-key one. A 401 on `/chat` auto-falls-back to `/demo/chat` regardless |
| `OPS_ASSISTANT_API_KEY` | gateway | only if using `/chat` | `X-API-Key` value; must equal operations-assistant's `API_KEY` |
| `OPS_ASSISTANT_TIMEOUT` | gateway | no (default `60`) | seconds to wait on a P2 response |
| `AUTH_MODE` | gateway | no (default `api_key`) | how the adapter authenticates to operations-assistant: `api_key` (the `X-API-Key` above) or `google_id_token` (a Google ID token minted for `OPS_ASSISTANT_URL`; Cloud Run only; no `/demo/chat` fallback). Anything else is an error. See section 4 |
| `OPS_ASSISTANT_PATH` | compose | no | filesystem path to the operations-assistant repo |
| `OPS_PERFORMANCE_PATH` | compose | no | filesystem path to the operations-performance repo |
| `GROQ_API_KEY` / `GEMINI_API_KEY` / `ANTHROPIC_API_KEY` | operations-assistant `.env` | one of them, for the trilogy | LLM provider key (all have free tiers) |

The gateway itself never needs an LLM key — it inspects traffic, it doesn't
generate text.

---

## Installing Docker (Windows)

1. Install **Docker Desktop for Windows**: <https://www.docker.com/products/docker-desktop/>
   (it enables the WSL2 backend during setup — accept that).
2. Reboot if prompted, launch Docker Desktop, wait for "Engine running".
3. Verify in a new terminal:
   ```bash
   docker --version
   docker compose version
   ```
4. Then `docker compose up --build` from this repo.
