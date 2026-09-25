"""
FastAPI gateway service. Real middleware, not a hardcoded-input script: any
caller can POST a prompt + session_id + backend name, and the gateway runs
the full pre-flight -> backend -> post-flight lifecycle before responding.

Backend selection via `backend` field proves pluggability at the API level,
not just in code -- swapping /gateway/chat's target is a request parameter,
not a redeploy.
"""
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import os

from gateway.adapters.stub_ops_agent import StubOpsAgentAdapter, FAKE_SYSTEM_PROMPT
from gateway.adapters.trivial_echo import TrivialEchoAdapter
from gateway.adapters.project2_agent_adapter import Project2AgentAdapter
from gateway.adapters.operations_assistant_adapter import (
    OpsAssistantAdapter,
    FAKE_SYSTEM_PROMPT as OPS_ASSISTANT_FAKE_SYSTEM_PROMPT,
)
from project2_agent.agent import FAKE_SYSTEM_PROMPT as PROJECT2_FAKE_SYSTEM_PROMPT
from gateway.actions.api import router as actions_router
from gateway.dashboard import router as dashboard_router
from gateway.demo import router as demo_router
from gateway.webui import router as webui_router
from gateway.middleware import GatewayMiddleware

app = FastAPI(title="LLM Security Gateway", version="0.1.0")
app.include_router(webui_router)
app.include_router(dashboard_router)
app.include_router(demo_router)
app.include_router(actions_router)

middleware = GatewayMiddleware()

BACKENDS = {
    "stub_ops_agent": (StubOpsAgentAdapter(), FAKE_SYSTEM_PROMPT),
    "trivial_echo": (TrivialEchoAdapter(), ""),
    "project2_agent": (Project2AgentAdapter(), PROJECT2_FAKE_SYSTEM_PROMPT),
}

# The real Project 2 (operations-assistant) is registered only when its URL is
# configured -- otherwise the free-tier deploy would advertise a backend that
# can't answer. Run it locally (docker compose) to get this one.
if os.environ.get("OPS_ASSISTANT_URL"):
    BACKENDS["operations_assistant"] = (OpsAssistantAdapter(), OPS_ASSISTANT_FAKE_SYSTEM_PROMPT)


class ChatRequest(BaseModel):
    prompt: str
    session_id: str
    role: str = "employee"
    backend: str = "stub_ops_agent"
    user_id: str = "unknown"


class ChatResponse(BaseModel):
    allowed: bool
    response: str | None
    block_reason: str | None
    trace: dict


@app.post("/gateway/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    if req.backend not in BACKENDS:
        return ChatResponse(
            allowed=False, response=None,
            block_reason=f"unknown_backend:{req.backend}",
            trace={"available_backends": list(BACKENDS.keys())},
        )

    adapter, system_prompt = BACKENDS[req.backend]
    result = middleware.process(
        prompt=req.prompt,
        session_id=req.session_id,
        backend=adapter,
        role=req.role,
        system_prompt=system_prompt,
        user_id=req.user_id,
    )
    return ChatResponse(
        allowed=result.allowed,
        response=result.response_text,
        block_reason=result.block_reason,
        trace=result.trace,
    )


@app.post("/gateway/chat/stream")
def chat_stream(req: ChatRequest):
    """Tier 3: streaming endpoint. Checks the response incrementally as it
    streams from the backend, cutting off mid-stream on a post-flight
    violation rather than waiting for the full response like /gateway/chat."""
    if req.backend not in BACKENDS:
        def error_gen():
            yield f"[unknown_backend:{req.backend}]"
        return StreamingResponse(error_gen(), media_type="text/plain")

    adapter, system_prompt = BACKENDS[req.backend]

    def event_gen():
        for event in middleware.process_streaming(
            prompt=req.prompt, session_id=req.session_id, backend=adapter,
            role=req.role, system_prompt=system_prompt, user_id=req.user_id,
        ):
            yield event["chunk"]
            if event["cut_off"]:
                break

    return StreamingResponse(event_gen(), media_type="text/plain")


@app.get("/gateway/backends")
def list_backends():
    return {"backends": [{"key": k, "name": adapter.name} for k, (adapter, _) in BACKENDS.items()]}


@app.get("/gateway/connectivity")
def connectivity():
    """Makes cross-service wiring observable, the way operations-assistant's
    /health reports whether it can reach operations-performance. In-process
    backends are always 'ok'; HTTP-backed ones expose a ping()."""
    out = {}
    for key, (adapter, _) in BACKENDS.items():
        ping = getattr(adapter, "ping", None)
        if callable(ping):
            ok, detail = ping()
            row = {"transport": "http", "reachable": ok, "detail": detail}
            if getattr(adapter, "chat_path", None):
                row["chat_path"] = adapter.chat_path
            out[key] = row
        else:
            out[key] = {"transport": "in_process", "reachable": True}
    return {
        "lite_mode": middleware.lite_mode,
        "ops_assistant_url": os.environ.get("OPS_ASSISTANT_URL") or None,
        "backends": out,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
