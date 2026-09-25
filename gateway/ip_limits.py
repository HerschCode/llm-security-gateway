"""
Client identification and per-IP rate limiting for the unauthenticated endpoints.

Two findings from the red-team pass (reports/redteam-2026-09.md) are fixed here:

  RT-01  All of the gateway's request limits (rate limit, burst detection, multi-turn split-payload tracking) were keyed only by
         the caller-supplied `session_id`. A client that sends a fresh session id on every request is never limited: 60 requests
         with rotating ids all went through, while 60 with one id were throttled after 19. A per-IP limit does not depend on
         anything the client chooses.
  RT-02  The demo endpoint took the FIRST value of `X-Forwarded-For` as the client IP. That header is client-controlled: any value
         the client sends ends up leftmost, so an attacker could rotate fake IPs to defeat an IP limit. The correct value is the
         one appended by a proxy YOU operate.

`client_ip` therefore ignores X-Forwarded-For unless TRUSTED_PROXY_HOPS is set to the number of proxies in front of the app; it
then takes the Nth value from the RIGHT (each trusted proxy appends the address it received the request from). With the default
of 0 the peer address is used, which behind a shared proxy means all clients look like one IP: a conservative, non-spoofable
default. The correct hop count for a real deployment must be verified against the actual header chain; it is not assumed here.

Limits are read from the environment on every request (so tests and operators can change them without a restart):
  GATEWAY_IP_RATE_LIMIT   requests per window per IP (default 120; 0 disables)
  GATEWAY_IP_RATE_WINDOW  window in seconds (default 60)
The counters are in memory and per process, like the rest of the gateway's state (see README "Known limitations").
"""
import os
import threading
import time
from collections import deque

from fastapi import HTTPException, Request

_LOCK = threading.Lock()
_HITS: dict[str, deque] = {}
_MAX_TRACKED = 5000


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        hops = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
    except ValueError:
        hops = 0
    if hops <= 0:
        return peer
    chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return chain[-hops] if len(chain) >= hops else peer


def ip_rate_limit(request: Request):
    """FastAPI dependency: 429 when this client IP has exceeded the per-window budget."""
    limit = int(os.environ.get("GATEWAY_IP_RATE_LIMIT", "120"))
    if limit <= 0:
        return
    window = float(os.environ.get("GATEWAY_IP_RATE_WINDOW", "60"))
    ip, now = client_ip(request), time.time()
    with _LOCK:
        hits = _HITS.setdefault(ip, deque())
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
            raise HTTPException(429, "rate limit exceeded for this client", headers={"Retry-After": str(int(window))})
        hits.append(now)
        if len(_HITS) > _MAX_TRACKED:                       # bound memory against a spray of source addresses
            for k in [k for k, v in _HITS.items() if not v or now - v[-1] > window]:
                del _HITS[k]
            while len(_HITS) > _MAX_TRACKED:
                _HITS.pop(next(iter(_HITS)))


def reset_for_tests():
    with _LOCK:
        _HITS.clear()
