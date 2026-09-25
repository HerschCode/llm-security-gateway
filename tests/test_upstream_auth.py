"""
AUTH_MODE -- how the gateway authenticates to operations-assistant.

Two layers, the same split the rest of this suite uses:

  * The helper (gateway/adapters/upstream_auth.py), with google.oauth2.id_token.fetch_id_token
    replaced by a fake and time driven by a fake clock. What is proved is what THIS code does with
    a token (attach it, cache it, refresh it near expiry, use the callee's URL as the audience,
    fail closed), not what Google does when it mints one.
  * The real adapter (gateway/adapters/operations_assistant_adapter.py) against an
    httpx.MockTransport, so the headers that actually go on the wire are inspected. The default
    mode (api_key) is pinned here too: setting no AUTH_MODE must behave exactly as before.

The mocked function is the real google.oauth2.id_token.fetch_id_token, so google-auth must be
installed (it is in requirements*.txt); nothing here talks to the network or the metadata server.

The helper section is the same as operations-assistant's tests/test_upstream_auth.py, because
gateway/adapters/upstream_auth.py is the same file as that repo's src/tools/upstream_auth.py.
"""

import base64
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.adapters import upstream_auth
from gateway.adapters.operations_assistant_adapter import BACKEND_ERROR_PREFIX, OpsAssistantAdapter
from gateway.adapters.upstream_auth import REFRESH_MARGIN_SECONDS, UpstreamAuthError

TARGET = "https://operations-assistant-123456789012.us-central1.run.app"
TOKEN_LIFETIME = 3600  # what Google issues


def make_jwt(**claims) -> str:
    """An unsigned three-part token in the JWT shape. The helper only reads `exp` from it."""
    def part(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.not-a-real-signature"


class Clock:
    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeFetchIdToken:
    """Stands in for google.oauth2.id_token.fetch_id_token: records how it was called and mints a
    distinct token (with a real `exp`, measured on the fake clock) every time."""

    def __init__(self, clock: Clock):
        self.clock = clock
        self.lifetime = TOKEN_LIFETIME
        self.delay = 0.0
        self.calls: list[tuple[object, str]] = []
        self.minted: list[str] = []

    def __call__(self, request, audience):
        self.calls.append((request, audience))
        if self.delay:
            time.sleep(self.delay)
        token = make_jwt(aud=audience, exp=self.clock.now + self.lifetime, n=len(self.calls))
        self.minted.append(token)
        return token

    @property
    def audiences(self) -> list[str]:
        return [audience for _, audience in self.calls]


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    monkeypatch.delenv("AUTH_MODE", raising=False)
    upstream_auth.clear_cache()
    yield
    upstream_auth.clear_cache()


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(upstream_auth, "_now", fake)
    return fake


@pytest.fixture
def fake_google(monkeypatch, clock):
    fake = FakeFetchIdToken(clock)
    monkeypatch.setattr("google.oauth2.id_token.fetch_id_token", fake)
    return fake


@pytest.fixture
def id_token_mode(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "google_id_token")


# ---------------------------------------------------------------------------
# Which mode is in effect
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (None, "api_key"),
    ("", "api_key"),
    ("   ", "api_key"),
    ("api_key", "api_key"),
    ("API_KEY", "api_key"),
    ("google_id_token", "google_id_token"),
    ("  Google_ID_Token ", "google_id_token"),
])
def test_auth_mode_reading(monkeypatch, raw, expected):
    if raw is not None:
        monkeypatch.setenv("AUTH_MODE", raw)
    assert upstream_auth.auth_mode() == expected


@pytest.mark.parametrize("raw", ["iam", "google", "google-id-token", "none", "true", "0"])
def test_an_unknown_mode_fails_closed(monkeypatch, fake_google, raw):
    """A typo must not silently downgrade the service to sending no credentials, or a stale key."""
    monkeypatch.setenv("AUTH_MODE", raw)
    with pytest.raises(UpstreamAuthError, match="AUTH_MODE"):
        upstream_auth.outbound_headers(TARGET, {"X-API-Key": "shared-secret"})
    assert fake_google.calls == []


# ---------------------------------------------------------------------------
# api_key (the default): behaviour is unchanged and Google is never involved
# ---------------------------------------------------------------------------

def test_default_mode_returns_exactly_the_static_headers_and_never_calls_google(fake_google):
    assert upstream_auth.outbound_headers(TARGET, {"X-API-Key": "shared-secret"}) == {"X-API-Key": "shared-secret"}
    assert upstream_auth.outbound_headers(TARGET) == {}
    assert fake_google.calls == []


def test_default_mode_hands_back_a_copy(fake_google):
    static = {"X-API-Key": "k"}
    headers = upstream_auth.outbound_headers(TARGET, static)
    headers["X-Extra"] = "1"
    assert static == {"X-API-Key": "k"}


# ---------------------------------------------------------------------------
# google_id_token: token attached, audience is the target URL
# ---------------------------------------------------------------------------

def test_id_token_mode_attaches_a_bearer_token_and_no_static_key(id_token_mode, fake_google):
    headers = upstream_auth.outbound_headers(TARGET, {"X-API-Key": "must-not-be-sent"})
    assert headers == {"Authorization": f"Bearer {fake_google.minted[0]}"}


def test_the_audience_is_the_target_url(id_token_mode, fake_google):
    upstream_auth.outbound_headers(TARGET)
    assert fake_google.audiences == [TARGET]


@pytest.mark.parametrize("url", [TARGET + "/", "  " + TARGET + "  ", TARGET + "///"])
def test_slashes_and_whitespace_do_not_change_the_audience(id_token_mode, fake_google, url):
    upstream_auth.id_token_for(url)
    assert fake_google.audiences == [TARGET]


def test_fetch_id_token_is_given_a_google_auth_request(id_token_mode, fake_google):
    import google.auth.transport.requests as google_requests
    upstream_auth.id_token_for(TARGET)
    assert isinstance(fake_google.calls[0][0], google_requests.Request)


@pytest.mark.parametrize("bad", ["", "   ", "/"])
def test_an_empty_audience_is_an_error_not_a_call(id_token_mode, fake_google, bad):
    with pytest.raises(UpstreamAuthError, match="audience"):
        upstream_auth.id_token_for(bad)
    assert fake_google.calls == []


# ---------------------------------------------------------------------------
# Caching, and refreshing near expiry
# ---------------------------------------------------------------------------

def test_the_token_is_reused_until_shortly_before_it_expires(id_token_mode, fake_google, clock):
    first = upstream_auth.id_token_for(TARGET)
    clock.advance(TOKEN_LIFETIME - REFRESH_MARGIN_SECONDS - 1)
    assert upstream_auth.id_token_for(TARGET) == first
    assert len(fake_google.calls) == 1


def test_the_token_is_refreshed_when_it_gets_near_expiry(id_token_mode, fake_google, clock):
    first = upstream_auth.id_token_for(TARGET)
    clock.advance(TOKEN_LIFETIME - REFRESH_MARGIN_SECONDS)  # the refresh point, still 5 minutes valid
    second = upstream_auth.id_token_for(TARGET)
    assert second != first
    assert len(fake_google.calls) == 2
    # and the new token is cached in turn
    assert upstream_auth.id_token_for(TARGET) == second
    assert len(fake_google.calls) == 2


def test_an_expired_token_is_never_served(id_token_mode, fake_google, clock):
    first = upstream_auth.id_token_for(TARGET)
    clock.advance(10 * TOKEN_LIFETIME)
    assert upstream_auth.id_token_for(TARGET) != first


def test_a_token_that_is_already_inside_the_margin_is_not_cached(id_token_mode, fake_google):
    fake_google.lifetime = REFRESH_MARGIN_SECONDS - 1
    upstream_auth.id_token_for(TARGET)
    upstream_auth.id_token_for(TARGET)
    assert len(fake_google.calls) == 2


def test_each_audience_has_its_own_token(id_token_mode, fake_google):
    a = upstream_auth.id_token_for("https://a.run.app")
    b = upstream_auth.id_token_for("https://b.run.app")
    assert a != b
    assert upstream_auth.id_token_for("https://a.run.app/") == a
    assert fake_google.audiences == ["https://a.run.app", "https://b.run.app"]


def test_a_token_with_no_readable_expiry_is_cached_only_briefly(id_token_mode, clock, monkeypatch):
    minted = []

    def opaque(request, audience):
        minted.append(audience)
        return f"opaque-token-{len(minted)}"

    monkeypatch.setattr("google.oauth2.id_token.fetch_id_token", opaque)
    assert upstream_auth.id_token_for(TARGET) == "opaque-token-1"
    assert upstream_auth.id_token_for(TARGET) == "opaque-token-1"
    clock.advance(upstream_auth._UNREADABLE_EXPIRY_LIFETIME_SECONDS)
    assert upstream_auth.id_token_for(TARGET) == "opaque-token-2"


@pytest.mark.parametrize("token", [
    "no-dots-at-all",
    "a.b",                                                              # payload is not base64 JSON
    "a.!!!.c",
    "a." + base64.urlsafe_b64encode(b"[1, 2]").decode() + ".c",         # JSON, but not an object
    "a." + base64.urlsafe_b64encode(b'{"aud": "x"}').decode() + ".c",   # no exp
    "a." + base64.urlsafe_b64encode(b'{"exp": "soon"}').decode() + ".c",
])
def test_unreadable_expiry_is_none_not_a_crash(token):
    assert upstream_auth._expiry(token) is None


def test_expiry_is_read_from_the_exp_claim():
    assert upstream_auth._expiry(make_jwt(exp=1234567890, aud="x")) == 1234567890.0


def test_concurrent_first_use_mints_one_token(id_token_mode, fake_google):
    fake_google.delay = 0.05
    with ThreadPoolExecutor(max_workers=8) as pool:
        tokens = list(pool.map(lambda _: upstream_auth.id_token_for(TARGET), range(8)))
    assert len(set(tokens)) == 1
    assert len(fake_google.calls) == 1


# ---------------------------------------------------------------------------
# Failure: one clear error, never an unauthenticated call
# ---------------------------------------------------------------------------

def test_a_failed_fetch_raises_one_clear_error_and_the_next_call_retries(id_token_mode, clock, monkeypatch):
    from google.auth import exceptions as google_exceptions
    attempts = []

    def flaky(request, audience):
        attempts.append(audience)
        if len(attempts) == 1:
            raise google_exceptions.DefaultCredentialsError("no metadata server here")
        return make_jwt(exp=clock.now + TOKEN_LIFETIME)

    monkeypatch.setattr("google.oauth2.id_token.fetch_id_token", flaky)
    with pytest.raises(UpstreamAuthError, match="no metadata server here") as failure:
        upstream_auth.id_token_for(TARGET)
    assert isinstance(failure.value.__cause__, google_exceptions.DefaultCredentialsError)
    assert "AUTH_MODE=api_key" in str(failure.value)  # tells the operator what to do locally

    assert upstream_auth.id_token_for(TARGET)  # nothing bad was cached
    assert len(attempts) == 2


def test_an_empty_token_is_an_error(id_token_mode, monkeypatch):
    monkeypatch.setattr("google.oauth2.id_token.fetch_id_token", lambda request, audience: "")
    with pytest.raises(UpstreamAuthError, match="empty"):
        upstream_auth.id_token_for(TARGET)


def test_missing_google_auth_is_reported_not_crashed_on(id_token_mode, monkeypatch):
    monkeypatch.setitem(sys.modules, "google.oauth2.id_token", None)  # makes the import raise
    with pytest.raises(UpstreamAuthError, match="google-auth"):
        upstream_auth.id_token_for(TARGET)


# ---------------------------------------------------------------------------
# The real adapter, with the actual headers inspected
# ---------------------------------------------------------------------------

_OK_BODY = {"answer": "SLA for P1 is 4 business hours.", "citations": [], "conversation_id": "s1"}


class Recorder:
    """An httpx.MockTransport handler that remembers each request it saw."""

    def __init__(self, status: int = 200, body=None):
        self.status = status
        self.body = _OK_BODY if body is None else body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)

    @property
    def paths(self) -> list[str]:
        return [request.url.path for request in self.requests]


def wire(monkeypatch, handler) -> None:
    """Route the adapter's httpx.post / httpx.get through a handler (the repo's existing pattern)."""
    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(httpx, "post", lambda url, **kw: client.post(url, **kw))
    monkeypatch.setattr(httpx, "get", lambda url, **kw: client.get(url, **kw))


def adapter(api_key: str = "", base_url: str = TARGET, chat_path: str = "/chat") -> OpsAssistantAdapter:
    return OpsAssistantAdapter(base_url=base_url, api_key=api_key, chat_path=chat_path)


@pytest.mark.parametrize("mode", [None, "api_key"])
def test_default_mode_sends_the_configured_key_as_it_always_did(monkeypatch, fake_google, mode):
    if mode:
        monkeypatch.setenv("AUTH_MODE", mode)
    server = Recorder()
    wire(monkeypatch, server)
    out = adapter(api_key="shared-secret").send("What is our SLA for P1?", session_id="abcdef123")
    request = server.requests[0]
    assert "SLA for P1" in out
    assert request.headers["x-api-key"] == "shared-secret"
    assert "authorization" not in request.headers
    assert request.headers["content-type"] == "application/json"
    assert fake_google.calls == []


def test_default_mode_without_a_key_sends_no_credentials(monkeypatch, fake_google):
    server = Recorder()
    wire(monkeypatch, server)
    adapter().send("hi", session_id="s1")
    assert "x-api-key" not in server.requests[0].headers
    assert "authorization" not in server.requests[0].headers
    assert fake_google.calls == []


def test_default_mode_a_401_still_falls_back_to_the_public_route(monkeypatch, fake_google):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(401 if request.url.path == "/chat" else 200, json=_OK_BODY)

    wire(monkeypatch, handler)
    out = adapter(api_key="wrong").send("hi", session_id="s1")
    assert calls == ["/chat", "/demo/chat"]
    assert not out.startswith(BACKEND_ERROR_PREFIX)


def test_id_token_mode_sends_a_token_minted_for_the_assistants_url(id_token_mode, monkeypatch, fake_google):
    server = Recorder()
    wire(monkeypatch, server)
    out = adapter(api_key="must-not-be-sent", base_url=TARGET + "/").send("hi", session_id="s1")
    request = server.requests[0]
    assert not out.startswith(BACKEND_ERROR_PREFIX)
    assert request.url.path == "/chat"
    assert request.headers["authorization"] == f"Bearer {fake_google.minted[0]}"
    assert "x-api-key" not in request.headers
    assert fake_google.audiences == [TARGET]


def test_id_token_mode_reuses_the_token_and_refreshes_it_near_expiry(id_token_mode, monkeypatch, fake_google, clock):
    server = Recorder()
    wire(monkeypatch, server)
    a = adapter()
    for _ in range(3):
        a.send("hi", session_id="s1")
    assert len(fake_google.calls) == 1
    assert len({request.headers["authorization"] for request in server.requests}) == 1

    clock.advance(TOKEN_LIFETIME - REFRESH_MARGIN_SECONDS)
    a.send("hi", session_id="s1")
    assert len(fake_google.calls) == 2
    assert server.requests[-1].headers["authorization"] == f"Bearer {fake_google.minted[1]}"


def test_id_token_mode_a_401_does_not_fall_back_to_the_anonymous_route(id_token_mode, monkeypatch, fake_google):
    server = Recorder(status=401)
    wire(monkeypatch, server)
    out = adapter().send("hi", session_id="s1")
    assert server.paths == ["/chat"]  # a credentials problem must not be hidden behind /demo/chat
    assert out.startswith(BACKEND_ERROR_PREFIX)
    assert "401" in out and "ID token" in out


def test_id_token_mode_a_403_names_the_missing_invoker_role(id_token_mode, monkeypatch, fake_google):
    server = Recorder(status=403)
    wire(monkeypatch, server)
    out = adapter().send("hi", session_id="s1")
    assert server.paths == ["/chat"]
    assert out.startswith(BACKEND_ERROR_PREFIX)
    assert "403" in out and "roles/run.invoker" in out


def test_no_token_means_a_backend_error_and_no_request(id_token_mode, monkeypatch):
    def no_identity(request, audience):
        raise RuntimeError("metadata server unreachable")

    monkeypatch.setattr("google.oauth2.id_token.fetch_id_token", no_identity)
    server = Recorder()
    wire(monkeypatch, server)
    out = adapter(api_key="shared-secret").send("hi", session_id="s1")  # must not raise, must not use the key
    assert out.startswith(BACKEND_ERROR_PREFIX)
    assert "could not authenticate" in out
    assert server.requests == []


def test_an_unknown_mode_fails_closed(monkeypatch, fake_google):
    monkeypatch.setenv("AUTH_MODE", "google_id_tokn")
    server = Recorder()
    wire(monkeypatch, server)
    out = adapter(api_key="shared-secret").send("hi", session_id="s1")
    assert out.startswith(BACKEND_ERROR_PREFIX)
    assert "AUTH_MODE" in out
    assert server.requests == []


def test_ping_default_mode_sends_no_credentials(monkeypatch, fake_google):
    server = Recorder(body={"status": "ok"})
    wire(monkeypatch, server)
    assert adapter().ping()[0] is True
    assert server.paths == ["/health"]
    assert "authorization" not in server.requests[0].headers
    assert fake_google.calls == []


def test_ping_id_token_mode_presents_a_token(id_token_mode, monkeypatch, fake_google):
    server = Recorder(body={"status": "ok"})
    wire(monkeypatch, server)
    assert adapter().ping()[0] is True
    assert server.requests[0].headers["authorization"] == f"Bearer {fake_google.minted[0]}"
    assert fake_google.audiences == [TARGET]


def test_ping_id_token_mode_reports_a_refusal_as_unreachable(id_token_mode, monkeypatch, fake_google):
    server = Recorder(status=403)
    wire(monkeypatch, server)
    reachable, detail = adapter().ping()
    assert reachable is False
    assert "403" in detail


def test_ping_never_raises_when_no_token_can_be_had(id_token_mode, monkeypatch):
    def no_identity(request, audience):
        raise RuntimeError("metadata server unreachable")

    monkeypatch.setattr("google.oauth2.id_token.fetch_id_token", no_identity)
    server = Recorder()
    wire(monkeypatch, server)
    reachable, detail = adapter().ping()
    assert reachable is False
    assert "UpstreamAuthError" in detail
    assert server.requests == []
