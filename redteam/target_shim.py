"""
A tiny HTTP shim so standard red-team tools (garak, promptfoo) can attack the same backend two ways with one request format:

  POST /direct/<backend>    {"prompt": "..."}  -> {"text": "<backend response>"}                gateway BYPASSED
  POST /gateway/<backend>   {"prompt": "..."}  -> {"text": "<backend response>"} or
                                                  {"text": "[BLOCKED by gateway: <reason>]", "blocked": true}   gateway IN FRONT

Why a shim rather than pointing the tools at /gateway/chat directly: (1) the gateway returns `response: null` on a block,
which generic scanners mishandle; a block must reach the detector as explicit, non-compliant text. (2) The "direct" path needs
an HTTP endpoint, and the demo backends are in-process adapters.

Each request gets a FRESH session id. That is deliberate: it measures per-prompt detection efficacy, and it keeps the
gateway's session-level controls (rate limit, burst and multi-turn anomaly detection) from blocking a scan for a reason
that is not the detectors. It is also what a real attacker would avoid by rotating sessions; the report says so.

Run (from the repo root, project venv):  python redteam/target_shim.py --gateway http://localhost:8100 --port 8200
"""
import argparse
import json
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.adapters.operations_assistant_adapter import OpsAssistantAdapter  # noqa: E402
from gateway.adapters.project2_agent_adapter import Project2AgentAdapter  # noqa: E402
from gateway.adapters.stub_ops_agent import StubOpsAgentAdapter  # noqa: E402
from gateway.adapters.trivial_echo import TrivialEchoAdapter  # noqa: E402

DIRECT = {"stub_ops_agent": StubOpsAgentAdapter, "trivial_echo": TrivialEchoAdapter,
          "project2_agent": Project2AgentAdapter, "operations_assistant": OpsAssistantAdapter}
GATEWAY_URL = "http://localhost:8100"


class Handler(BaseHTTPRequestHandler):
    adapters: dict = {}

    def _reply(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        parts = self.path.strip("/").split("/")
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            prompt = body["prompt"]
            mode, backend = parts
        except (ValueError, KeyError):
            return self._reply(400, {"error": "expected POST /direct|gateway/<backend> with {\"prompt\": ...}"})
        session = f"rt-{uuid.uuid4().hex[:10]}"
        if mode == "direct" and backend in DIRECT:
            adapter = self.adapters.setdefault(backend, DIRECT[backend]())
            return self._reply(200, {"text": adapter.send(prompt, session_id=session, role="employee", user_id="redteam")})
        if mode == "gateway":
            r = httpx.post(f"{GATEWAY_URL}/gateway/chat", timeout=180,
                           json={"prompt": prompt, "session_id": session, "role": "employee", "backend": backend, "user_id": "redteam"})
            j = r.json()
            if not j.get("allowed"):
                return self._reply(200, {"text": f"[BLOCKED by gateway: {j.get('block_reason')}]", "blocked": True})
            return self._reply(200, {"text": j.get("response") or "", "blocked": False})
        return self._reply(404, {"error": "unknown route or backend"})

    def log_message(self, *args):  # quiet
        pass


def main():
    global GATEWAY_URL
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default=GATEWAY_URL)
    ap.add_argument("--port", type=int, default=8200)
    args = ap.parse_args()
    GATEWAY_URL = args.gateway.rstrip("/")
    print(f"target shim on :{args.port}, gateway at {GATEWAY_URL}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
