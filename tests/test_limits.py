"""Input size limits (gateway/limits.py): an oversized request is refused before any detector runs."""
import pytest
from fastapi.testclient import TestClient

from gateway import ip_limits
from gateway.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _no_ip_limit(monkeypatch):
    monkeypatch.setenv("GATEWAY_IP_RATE_LIMIT", "0")
    ip_limits.reset_for_tests()
    yield
    ip_limits.reset_for_tests()


def chat(prompt="What is the status of order 12345?", **kw):
    body = {"prompt": prompt, "session_id": "lim", "backend": "trivial_echo", **kw}
    return client.post("/gateway/chat", json=body)


def test_a_normal_request_is_unaffected():
    r = chat()
    assert r.status_code == 200 and r.json()["allowed"] is True


def test_a_prompt_over_the_limit_is_a_422_and_no_detector_ran(monkeypatch):
    calls = []
    from gateway import middleware as mw_mod
    monkeypatch.setattr(mw_mod.GatewayMiddleware, "_run_injection_ensemble", lambda *a, **k: calls.append(1) or (False, None, None, {}))
    r = chat("x" * 20_001)
    assert r.status_code == 422 and "longer than 20000" in r.text
    assert calls == []


def test_a_prompt_at_the_limit_is_accepted():
    assert chat("a" * 20_000).status_code == 200


def test_the_prompt_limit_is_tunable_per_request(monkeypatch):
    monkeypatch.setenv("GATEWAY_MAX_PROMPT_CHARS", "50")
    assert chat("y" * 51).status_code == 422
    assert chat("y" * 50).status_code == 200


@pytest.mark.parametrize("field,value", [("session_id", "s" * 129), ("session_id", ""), ("role", "r" * 33), ("backend", "b" * 65), ("user_id", "u" * 129)])
def test_identity_fields_are_bounded(field, value):
    body = {"prompt": "hi", "session_id": "lim", "backend": "trivial_echo", field: value}
    assert client.post("/gateway/chat", json=body).status_code == 422


def test_a_declared_content_length_over_the_limit_is_a_413_without_reading_the_body(monkeypatch):
    monkeypatch.setenv("GATEWAY_MAX_BODY_BYTES", "1000")
    r = client.post("/gateway/chat", content=b"{" + b" " * 2000 + b"}", headers={"content-type": "application/json"})
    assert r.status_code == 413 and "larger than 1000" in r.text


def test_a_chunked_body_that_streams_past_the_limit_is_cut_off(monkeypatch):
    """No Content-Length: the limit has to be enforced as the bytes arrive."""
    monkeypatch.setenv("GATEWAY_MAX_BODY_BYTES", "1000")

    def body():
        yield b'{"prompt": "'
        for _ in range(50):
            yield b"a" * 100
        yield b'", "session_id": "s"}'

    r = client.post("/gateway/chat", content=body(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_the_body_limit_applies_to_every_route(monkeypatch):
    monkeypatch.setenv("GATEWAY_MAX_BODY_BYTES", "200")
    r = client.post("/gateway/actions/authorize", content=b"{" + b" " * 500 + b"}", headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_zero_disables_the_body_limit(monkeypatch):
    monkeypatch.setenv("GATEWAY_MAX_BODY_BYTES", "0")
    assert chat("z" * 10_000).status_code == 200


def test_get_requests_and_health_are_untouched():
    assert client.get("/health").status_code == 200
