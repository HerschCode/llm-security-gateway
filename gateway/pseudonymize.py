"""
Reversible pseudonymization: tokenize PII before the model sees it, restore it in the response for authorized roles.

    PII_MODE=redact          (default) PII is replaced by [REDACTED_<TYPE>] and is gone.
    PII_MODE=pseudonymize    PII is replaced by a stable token, <<EMAIL_1_a3f9c2>>, kept in a per-session vault, and the response is
                             detokenized for roles listed in PII_DETOKENIZE_ROLES (default "manager,admin"); other roles keep the tokens.

Why tokens rather than redaction: the model can still reason about identity ("the same email appears twice", "send it to the requester")
without ever seeing the value, and an authorized reader gets a usable answer back.

Security properties, and their limits (docs/pii-evaluation.md, SECURITY.md when Phase 6 lands):
  * Originals live only in this process's memory: never logged, never written to disk, never in the audit trail (which records types only).
  * Tokens carry a per-session random nonce. A token from another session, or a forged one, does not resolve. The counter part is
    guessable, so the nonce is what stops forging, and the nonce is only ever shown to the session that owns it.
  * A session's vault also remembers which user_id created it; a different user_id does not get values back. Identity here is asserted by the
    caller (the gateway does not authenticate principals), so this catches mix-ups, not a spoofing attacker who also knows the session id.
  * Bounded: per-session value cap (further PII in that session falls back to plain redaction), a session cap (oldest evicted), and a TTL.
  * Streaming: a token split across chunks is held back until it completes, so no partial token is ever emitted.
"""
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

TOKEN_RE = re.compile(r"<<([A-Z_]+)_(\d{1,4})_([0-9a-f]{6})>>")
MAX_TOKEN_LEN = 40


def mode() -> str:
    m = os.environ.get("PII_MODE", "redact")
    if m not in ("redact", "pseudonymize"):
        raise ValueError(f"PII_MODE must be redact or pseudonymize, got {m!r}")
    return m


def detokenize_roles() -> set[str]:
    return {r.strip() for r in os.environ.get("PII_DETOKENIZE_ROLES", "manager,admin").split(",") if r.strip()}


def _identity_key(pii_type: str, value: str) -> str:
    if pii_type in ("phone", "credit_card", "aadhaar"):
        return "".join(c for c in value if c.isdigit() or c == "+")
    return " ".join(value.split()).lower()


@dataclass
class _SessionVault:
    owner: str
    nonce: str = field(default_factory=lambda: secrets.token_hex(3))
    values: dict = field(default_factory=dict)          # token -> original
    index: dict = field(default_factory=dict)           # (type, identity key) -> token
    counters: dict = field(default_factory=dict)
    last_used: float = field(default_factory=time.time)


class PseudonymVault:
    def __init__(self, ttl_seconds: float = 3600.0, max_sessions: int = 500, max_values_per_session: int = 200):
        self.ttl, self.max_sessions, self.max_values = ttl_seconds, max_sessions, max_values_per_session
        self._sessions: OrderedDict[str, _SessionVault] = OrderedDict()
        self._lock = threading.Lock()

    def __repr__(self):                                     # never print stored values
        return f"<PseudonymVault sessions={len(self._sessions)}>"

    # ---- housekeeping ---------------------------------------------------------------------------------
    def _expire(self, now: float):
        for sid in [s for s, v in self._sessions.items() if now - v.last_used > self.ttl]:
            del self._sessions[sid]

    def _get(self, session_id: str, owner: str, create: bool):
        now = time.time()
        self._expire(now)
        v = self._sessions.get(session_id)
        if v is None and create:
            v = self._sessions[session_id] = _SessionVault(owner=owner)
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        if v is not None:
            v.last_used = now
            self._sessions.move_to_end(session_id)
        return v

    def forget(self, session_id: str):
        with self._lock:
            self._sessions.pop(session_id, None)

    def stats(self) -> dict:
        with self._lock:
            return {"sessions": len(self._sessions), "values": sum(len(v.values) for v in self._sessions.values())}

    # ---- tokenize / detokenize -----------------------------------------------------------------------------
    def tokenize(self, session_id: str, owner: str, text: str, spans) -> str:
        """`text` with each span replaced by its session token. Spans must be non-overlapping and in text order."""
        if not spans:
            return text
        with self._lock:
            v = self._get(session_id, owner, create=True)
            out, pos = [], 0
            for s in spans:
                out.append(text[pos:s.start])
                original = text[s.start:s.end]
                key = (s.type, _identity_key(s.type, original))
                token = v.index.get(key)
                if token is None and len(v.values) < self.max_values and v.owner == owner:
                    n = v.counters[s.type] = v.counters.get(s.type, 0) + 1
                    token = f"<<{s.type.upper()}_{n}_{v.nonce}>>"
                    v.values[token] = original
                    v.index[key] = token
                out.append(token if token else f"[REDACTED_{s.type.upper()}]")          # cap reached or foreign owner: plain redaction
                pos = s.end
            out.append(text[pos:])
            return "".join(out)

    def detokenize(self, session_id: str, owner: str, text: str) -> str:
        if "<<" not in text:
            return text
        with self._lock:
            v = self._get(session_id, owner, create=False)
            if v is None or v.owner != owner:
                return text
            return TOKEN_RE.sub(lambda m: v.values.get(m.group(0), m.group(0)), text)

    def stream_detokenizer(self, session_id: str, owner: str, enabled: bool = True) -> "StreamDetokenizer":
        return StreamDetokenizer(self, session_id, owner, enabled)


class StreamDetokenizer:
    """Feed chunks in, get text out with tokens restored. A token that has started but not finished is held back."""

    def __init__(self, vault: PseudonymVault, session_id: str, owner: str, enabled: bool = True):
        self.vault, self.session_id, self.owner, self.enabled = vault, session_id, owner, enabled
        self._buf = ""

    def _restore(self, text: str) -> str:
        return self.vault.detokenize(self.session_id, self.owner, text) if self.enabled else text

    def feed(self, chunk: str) -> str:
        if not self.enabled:
            return chunk
        self._buf += chunk
        cut = len(self._buf)
        i = self._buf.rfind("<<")
        if i != -1 and ">>" not in self._buf[i:] and len(self._buf) - i <= MAX_TOKEN_LEN:
            cut = i                                              # an unfinished token: keep it for the next chunk
        elif self._buf.endswith("<"):
            cut = len(self._buf) - 1                             # could be the first half of "<<"
        out, self._buf = self._buf[:cut], self._buf[cut:]
        return self._restore(out)

    def flush(self) -> str:
        rest, self._buf = self._buf, ""
        return self._restore(rest)
