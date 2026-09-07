"""Contract tests for the real-Project-2 HTTP adapter: request shape, the
401 -> /demo/chat fallback, and the ping() reachability check. Uses httpx's
MockTransport so the adapter's real request/response/error handling runs."""
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.adapters.operations_assistant_adapter import (
    OpsAssistantAdapter, BACKEND_ERROR_PREFIX, _norm_path,
)


@pytest.mark.parametrize("raw,expected", [
    ("/chat", "/chat"),
    ("chat", "/chat"),
    ("/demo/chat", "/demo/chat"),
    ("demo/chat", "/demo/chat"),
    ("C:/Program Files/Git/demo/chat", "/demo/chat"),  # Git-Bash mangled a leading slash
    ("", "/chat"),
])
def test_norm_path_tolerates_shell_mangling(raw, expected):
    assert _norm_path(raw) == expected

_OK_BODY = {"answer": "SLA for P1 is 4 business hours.",
            "tools_used": ["search_policy_documents"],
            "citations": [{"kind": "document", "reference": "SLA Policy 1.2"}],
            "conversation_id": "demo"}


def _client_with(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_posts_question_and_parses_answer_with_citations(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["json"] = request.read().decode()
        return httpx.Response(200, json=_OK_BODY)

    monkeypatch.setattr(httpx, "post", lambda url, **kw: _client_with(handler).post(url, **kw))
    a = OpsAssistantAdapter(base_url="http://p2.test", api_key="", chat_path="/chat")
    out = a.send("What is our SLA for P1?", session_id="abcdef123")

    assert seen["url"] == "http://p2.test/chat"
    assert '"question"' in seen["json"]
    assert "SLA for P1 is 4 business hours." in out
    assert "SLA Policy 1.2" in out


def test_401_on_chat_falls_back_to_demo_chat(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/chat":
            return httpx.Response(401, json={"detail": "Missing or invalid X-API-Key header"})
        return httpx.Response(200, json=_OK_BODY)

    monkeypatch.setattr(httpx, "post", lambda url, **kw: _client_with(handler).post(url, **kw))
    a = OpsAssistantAdapter(base_url="http://p2.test", api_key="wrong", chat_path="/chat")
    out = a.send("hi", session_id="s1")

    assert calls == ["/chat", "/demo/chat"]
    assert not out.startswith(BACKEND_ERROR_PREFIX)
    assert "SLA for P1" in out


def test_persistent_401_reports_backend_error_with_hint(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "nope"})

    monkeypatch.setattr(httpx, "post", lambda url, **kw: _client_with(handler).post(url, **kw))
    a = OpsAssistantAdapter(base_url="http://p2.test", api_key="", chat_path="/demo/chat")
    out = a.send("hi", session_id="s1")
    assert out.startswith(BACKEND_ERROR_PREFIX)
    assert "401" in out


def test_ping_reports_reachability(monkeypatch):
    def ok(url, **kw):
        return _client_with(lambda r: httpx.Response(200, json={"status": "ok"})).get(url, **kw)

    monkeypatch.setattr(httpx, "get", ok)
    reachable, detail = OpsAssistantAdapter(base_url="http://p2.test").ping()
    assert reachable is True

    assert OpsAssistantAdapter(base_url="").ping()[0] is False
