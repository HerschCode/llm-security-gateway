"""
How this service proves its own identity to the service it calls (outbound auth).

Selected with the AUTH_MODE environment variable:

    api_key          The default, and exactly what this service did before AUTH_MODE existed:
                     a static key in an X-API-Key header, if one is configured.
    google_id_token  A short-lived, Google-signed ID token sent as "Authorization: Bearer
                     <token>", minted for the URL of the service being called (the token's
                     "audience"). There is no shared secret to store, rotate or leak: on Cloud
                     Run the token comes from the metadata server for the service account
                     attached to the revision, and the callee's Cloud Run IAM check
                     (roles/run.invoker) decides whether that identity may call it. See
                     https://github.com/HerschCode/northstar-infra for the infrastructure side.

Any other value is an error, not a silent fallback: a typo must not quietly downgrade a
service to sending no credentials at all.

fetch_id_token() is a network call to the metadata server, so tokens are cached per audience and
reused until shortly before their own `exp` claim (Google issues them for an hour). google-auth is
imported lazily, so the default mode, local development and most of the test suite need nothing
they didn't already have.

This file is deliberately identical in operations-assistant and llm-security-gateway (separate
repositories, no shared package): change one, change both.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from typing import Mapping

log = logging.getLogger(__name__)

API_KEY = "api_key"
GOOGLE_ID_TOKEN = "google_id_token"
MODES = (API_KEY, GOOGLE_ID_TOKEN)

# Ask for a new token this long before the current one expires, so a request that starts just
# before the deadline never reaches the callee carrying an already-expired token.
REFRESH_MARGIN_SECONDS = 300
# Google's ID tokens last an hour. This is only used if a token's own expiry can't be read.
_UNREADABLE_EXPIRY_LIFETIME_SECONDS = 300


class UpstreamAuthError(RuntimeError):
    """The credentials for the configured AUTH_MODE could not be produced. Callers turn this into
    their own "upstream unavailable" error; they must not send the request without credentials."""


def auth_mode() -> str:
    """The mode in effect, read on every call so it can change without a reload (tests do)."""
    mode = os.environ.get("AUTH_MODE", "").strip().lower() or API_KEY
    if mode not in MODES:
        raise UpstreamAuthError(f"AUTH_MODE={mode!r} is not one of: {', '.join(MODES)}")
    return mode


def outbound_headers(audience: str, api_key_headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """Headers that authenticate a call to the service whose base URL is `audience`.

    api_key mode returns `api_key_headers` unchanged, so callers keep sending whatever they sent
    before. google_id_token mode returns the Authorization header and nothing else: the point of
    the mode is that no static key is involved.
    """
    if auth_mode() == GOOGLE_ID_TOKEN:
        return {"Authorization": f"Bearer {id_token_for(audience)}"}
    return dict(api_key_headers or {})


_lock = threading.Lock()
_cache: dict[str, tuple[str, float]] = {}  # audience -> (token, moment to ask for a new one)


def _now() -> float:
    return time.time()


def id_token_for(audience: str) -> str:
    """A Google ID token for `audience`, straight from the cache while it is comfortably valid."""
    audience = audience.strip().rstrip("/")
    if not audience:
        raise UpstreamAuthError("no audience to mint an ID token for (the target service URL is empty)")
    # One lock, held across the fetch: when a token lapses, concurrent requests wait for the one
    # refresh instead of each calling the metadata server.
    with _lock:
        now = _now()
        cached = _cache.get(audience)
        if cached is not None and now < cached[1]:
            return cached[0]
        token = _fetch(audience)
        refresh_at = _refresh_at(token, now)
        _cache[audience] = (token, refresh_at)
        log.debug("minted a Google ID token for %s; refreshing in %ds", audience, refresh_at - now)
        return token


def clear_cache() -> None:
    """Forget every cached token (used by tests; also forces a refresh)."""
    with _lock:
        _cache.clear()


def _fetch(audience: str) -> str:
    try:
        import google.auth.transport.requests
        import google.oauth2.id_token
    except ImportError as exc:
        raise UpstreamAuthError(
            "AUTH_MODE=google_id_token needs the google-auth and requests packages"
        ) from exc
    try:
        token = google.oauth2.id_token.fetch_id_token(google.auth.transport.requests.Request(), audience)
    except Exception as exc:  # google-auth raises a family of errors; callers need just one
        raise UpstreamAuthError(
            f"could not get a Google ID token for {audience} ({type(exc).__name__}: {exc}). "
            "AUTH_MODE=google_id_token needs a Google service-account identity, i.e. Cloud Run; "
            "use AUTH_MODE=api_key anywhere else."
        ) from exc
    if not token:
        raise UpstreamAuthError(f"Google returned an empty ID token for {audience}")
    return token


def _refresh_at(token: str, now: float) -> float:
    expires = _expiry(token)
    if expires is None:
        return now + _UNREADABLE_EXPIRY_LIFETIME_SECONDS
    return expires - REFRESH_MARGIN_SECONDS


def _expiry(token: str) -> float | None:
    """The token's `exp` claim (seconds since the epoch), read WITHOUT verifying the signature:
    this is a token this process just minted for itself, and the value only decides when to ask
    for another one."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return float(claims["exp"])
    except (IndexError, KeyError, TypeError, ValueError):
        return None
