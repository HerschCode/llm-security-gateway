# Deploying / Running the LLM Security Gateway

Three ways to run it, smallest to largest.

| Setup | Layers | Backends | Needs | Use for |
|---|---|---|---|---|
| **Render free tier** | rule_based + embedding (lite mode) | stub_ops_agent, project2_agent | nothing | public link for recruiters |
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
- **Lite mode**: the torch-backed scratch classifier (layer 3) is disabled to fit
  in 512MB. The live demo is the ensemble *minus* the one ML layer that was doing
  real work (see `docs/comparison_table.md`). The full pipeline is what
  `docker compose up` runs.
- Spins down after ~15 min idle; the next request takes ~30-60s to wake.

**No API keys.** `render.yaml` points `OPS_ASSISTANT_URL` at the deployed
operations-assistant and uses its **public, keyless, IP-rate-limited**
`/demo/chat` endpoint (`OPS_ASSISTANT_CHAT_PATH=/demo/chat`) — so the
`operations_assistant` backend works in the live demo without any secret. Remove
those two lines from `render.yaml` to hide that backend instead.

Check wiring any time at `…/gateway/connectivity` — it reports, per backend,
whether the gateway can actually reach it.

---

## 2. Full pipeline locally (`docker compose up`)

All three detection layers, no external services.

```bash
docker compose up --build
# open http://localhost:8000/gateway/demo
```

`GATEWAY_LITE=0` in `docker-compose.yml` → torch classifier active. This is the
setup to screen-record: pick an attack, watch all three layer chips, watch the
gateway block what the backend alone leaks.

---

## 3. The trilogy, end to end (`docker-compose.trilogy.yml`)

```
caller → [ P3: LLM Security Gateway ] → [ P2: operations-assistant ] → [ P1: operations-performance API ]
```

### Prerequisites

1. **All three repos** checked out. If `operations-assistant` is not at
   `../../0_Project/operations-assistant/operations-assistant` relative to this
   repo, set `OPS_ASSISTANT_PATH` to its actual path (env var or a `.env` next to
   this file).
2. **`operations-assistant/.env`** with a free Groq key
   ([console.groq.com](https://console.groq.com/keys)):
   ```
   AGENT_PROVIDER=groq
   AGENT_MODEL=llama-3.3-70b-versatile
   GROQ_API_KEY=gsk_...
   ```
   (Gemini works too: `AGENT_PROVIDER=gemini`, `AGENT_MODEL=gemini-1.5-flash`,
   `GEMINI_API_KEY=...` from [aistudio.google.com/apikey](https://aistudio.google.com/apikey).
   Anthropic: `AGENT_PROVIDER=anthropic`, `ANTHROPIC_API_KEY=sk-ant-...`.)
3. **Project 1's API** running on the host at `:8000`
   (`cd operations-performance && python -m scripts.run_analysis`). Without it,
   P2's data/analytics tools return "insufficient data" and only its
   RAG/document answers work — still enough to demo the gateway in front of a
   real LLM agent.
4. **First run only** — build P2's vector index:
   ```bash
   docker compose -f docker-compose.trilogy.yml run --rm operations-assistant \
     python -m scripts.index_documents
   ```

### Run

```bash
docker compose -f docker-compose.trilogy.yml up --build
# open http://localhost:8080/gateway/demo  → pick the "operations_assistant" backend
```

---

## Environment variables (reference)

| Var | Where | Required? | What |
|---|---|---|---|
| `GATEWAY_LITE` | gateway | no (default `0`) | `1` disables the torch classifier layer |
| `PORT` | gateway | no (default `8000`) | Render sets this automatically |
| `OPS_ASSISTANT_URL` | gateway | only for the real-P2 backend | e.g. `http://operations-assistant:8001`; if unset the backend is not registered |
| `OPS_ASSISTANT_CHAT_PATH` | gateway | no (default `/chat`) | set to `/demo/chat` to use P2's keyless public endpoint instead of the API-key one. A 401 on `/chat` auto-falls-back to `/demo/chat` regardless |
| `OPS_ASSISTANT_API_KEY` | gateway | only if using `/chat` | `X-API-Key` value; must equal operations-assistant's `API_KEY` |
| `OPS_ASSISTANT_TIMEOUT` | gateway | no (default `60`) | seconds to wait on a P2 response |
| `OPS_ASSISTANT_PATH` | compose | no | filesystem path to the operations-assistant repo |
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
