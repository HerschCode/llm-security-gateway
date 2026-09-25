"""
Input size limits (SEC-01 in docs/security-scans.md, found while writing the threat model, not by a scanner).

Before this, nothing bounded a request: `ChatRequest.prompt` was an unbounded string, and the body was not limited, so one request with a
100 MB prompt went through the PII regexes, the normalizer and the classifier on a 512 MB instance, and the session context tracker would
have kept it. Two layers now:

  * field limits on the chat request (Pydantic): prompt GATEWAY_MAX_PROMPT_CHARS (default 20,000 characters), session_id and user_id 128,
    role 32, backend 64. A violation is a 422 before any detector runs.
  * a body limit for every route, GATEWAY_MAX_BODY_BYTES (default 262,144): a Content-Length above it is a 413 without reading the body,
    and a body that streams past it without a Content-Length (chunked) is cut off with a 413 as soon as it crosses the limit.

Both are read on every request, so they can be tuned without a code change; 0 disables the body limit (not recommended).
"""
import json
import os

MAX_PROMPT_CHARS_DEFAULT = 20_000
MAX_BODY_BYTES_DEFAULT = 262_144


def max_prompt_chars() -> int:
    return int(os.environ.get("GATEWAY_MAX_PROMPT_CHARS", MAX_PROMPT_CHARS_DEFAULT))


def max_body_bytes() -> int:
    return int(os.environ.get("GATEWAY_MAX_BODY_BYTES", MAX_BODY_BYTES_DEFAULT))


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Pure ASGI middleware (so it sees the body as it arrives, not after the framework has buffered it)."""

    def __init__(self, app):
        self.app = app

    async def _reject(self, send, limit: int):
        body = json.dumps({"detail": f"request body larger than {limit} bytes"}).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        limit = max_body_bytes()
        if scope["type"] != "http" or limit <= 0:
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            return await self._reject(send, limit)

        received = 0
        started = False
        exceeded = False
        replaced = False

        async def limited_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _TooLarge()
            return message

        async def tracking_send(message):
            nonlocal started, replaced
            if replaced:
                return                                    # the app's own (error) response is discarded
            if exceeded and message["type"] == "http.response.start" and not started:
                # The framework caught our exception while parsing the body and answered with its own 400: replace it with the 413.
                replaced = started = True
                await self._reject(send, limit)
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send, limit)
