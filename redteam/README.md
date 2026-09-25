# Red-team harness

Reproduces the 2026-09 red-team exercise reported in [`reports/redteam-2026-09.md`](../reports/redteam-2026-09.md). Everything is free-tier: garak and
promptfoo are open source, the LLM-backed target and the adaptive attacker use `openai/gpt-oss-120b` on Groq's free tier.
Raw run output (`redteam/runs/`, garak reports, logs, the approvals database) is gitignored; condensed results are committed under `reports/redteam/`.

| File | Purpose |
|---|---|
| `target_shim.py` | HTTP shim so scanners can hit the same backend two ways: `POST /direct/<backend>` (gateway bypassed) and `POST /gateway/<backend>` (gateway in front). A gateway block is returned as explicit text `[BLOCKED by gateway: ...]`. Every request gets a fresh session id (see the report's limitations). |
| `garak/*.json`, `garak/run.yaml` | garak REST generator configs (one per mode and backend) and run settings (25 prompts per probe, seed fixed). |
| `run_garak.py` | Runs a probe set against one target and summarises it. An attack counts as **successful only if it was not blocked and garak's detector fired**. |
| `promptfoo/` | promptfoo (pinned `0.119.0`) in eval mode with a static, hand-written attack suite and leak/compliance assertions. |
| `adaptive_attacker.py` | LLM attacker + LLM victim agent iterating against the real `ActionFirewall` (6 goals x N turns). |
| `mutation_attacker.py` | Deterministic, offline attacker: 74 mutated calls (identifier obfuscation, tool/argument-name variants, type confusion, encoded exfiltration) against the action firewall. Not adaptive. Its cases are pinned in `tests/test_action_mutations.py`. |
| `summarize.py` | Condenses `runs/` into `reports/redteam/`. |

## Setup

```bash
# garak lives in its own venv (large dependency tree; torch, transformers, ...)
python -m venv redteam/.venv-garak
redteam/.venv-garak/Scripts/python.exe -m pip install garak          # tested with garak 0.16.0

# gateway and shim (project venv). Disable the per-IP limit for scans; a scan is one client sending thousands of requests.
export GATEWAY_IP_RATE_LIMIT=0 DEMO_RATE_LIMIT=100000
python -m uvicorn gateway.app:app --port 8100 &
python redteam/target_shim.py --gateway http://127.0.0.1:8100 --port 8200 &
```

Use `127.0.0.1`, not `localhost`: on Windows `localhost` resolves to IPv6 first and every request paid a ~4 s timeout before falling back.

To scan the real, LLM-backed operations-assistant, run it locally (`uvicorn src.api.main:app --port 8001`) and start the gateway and shim with
`OPS_ASSISTANT_URL=http://127.0.0.1:8001 OPS_ASSISTANT_CHAT_PATH=/chat OPS_ASSISTANT_API_KEY=<its API key>`. Its public `/demo/chat` endpoint
allows only 5 requests per 10 minutes per IP, so it cannot be scanned.

## Run

```bash
python redteam/run_garak.py --mode gateway --backend stub_ops_agent --tag gw-stub          # 20 probes, ~500 prompts
python redteam/run_garak.py --mode direct  --backend stub_ops_agent --tag direct-stub
python redteam/run_garak.py --mode gateway --backend operations_assistant --tag gw-p2 --set small --cap 8   # token-limited LLM target
(cd redteam/promptfoo && npx promptfoo@0.119.0 eval -c promptfooconfig.yaml --no-cache -o ../runs/promptfoo.json)
GROQ_API_KEY=... python redteam/adaptive_attacker.py --turns 5 --victim naive  --out redteam/runs/adaptive-naive.json
GROQ_API_KEY=... python redteam/adaptive_attacker.py --turns 3 --victim robust --out redteam/runs/adaptive-robust.json
GROQ_API_KEY=... python redteam/adaptive_attacker.py --turns 8 --victim compromised --attacker-model openai/gpt-oss-20b --out redteam/runs/adaptive-compromised.json
python redteam/mutation_attacker.py                                                       # offline, no LLM
python redteam/summarize.py
```

## Caveats worth knowing before reading any number

- The `stub_ops_agent` backend is a keyword-triggered stand-in, not an LLM. Its "attack success" is meaningless for probe families it has no
  trigger for. The **gateway's block rate** is independent of the backend and is the useful number there; attack success is only meaningful on
  the real LLM-backed target.
- garak's `encoding.*` probes try to make a model *emit* a given string (slurs, HTML/JS, shell commands). That is not the instruction-override
  threat the gateway's detectors target, so their block rate is not a detection metric.
- The promptfoo suite was written by the gateway's author. Its 100% is not comparable with garak's third-party probes.
- The adaptive attacker is quota-limited (Groq's daily token limit is per model; `--attacker-model` / `--victim-model` switch models) and the 20b model
  returned unusable output on about a third of turns. Compromised mode assumes the agent is already hijacked, so its "text layers alone" column is
  true by construction. See the report's limitations.
- Small samples throughout (8 to 25 prompts per probe on the LLM target, 5 turns per adaptive goal): a zero means "not found here".
