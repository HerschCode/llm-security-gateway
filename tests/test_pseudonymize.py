"""Reversible pseudonymization (gateway/pseudonymize.py) and its wiring into the middleware (PII_MODE=pseudonymize)."""
import re
import time

import pytest

from gateway import pseudonymize
from gateway.adapters.base import BackendAdapter
from gateway.pii import PIISpan, detect_spans
from gateway.pseudonymize import TOKEN_RE, PseudonymVault

EMAIL = "olivia.anderson@company.co.in"
AADHAAR = "2363 2363 2363"
TEXT = f"Mail {EMAIL} about Aadhaar {AADHAAR} today, cc {EMAIL.upper()}."


def spans_of(text):
    return detect_spans(text)


@pytest.fixture
def vault():
    return PseudonymVault()


def tok(vault, text=TEXT, session="s1", owner="u1"):
    return vault.tokenize(session, owner, text, spans_of(text))


# ---- the vault ------------------------------------------------------------------------------------------------------------------

def test_round_trip_restores_the_original_text(vault):
    text = f"Mail {EMAIL} about Aadhaar {AADHAAR} today, phone +91 98765 43210."
    tokenized = tok(vault, text)
    assert EMAIL not in tokenized and AADHAAR not in tokenized and "98765" not in tokenized
    assert vault.detokenize("s1", "u1", tokenized) == text


def test_a_repeated_value_comes_back_in_the_form_it_was_first_written(vault):
    """One identity, one token: a later mention in a different case or format is restored as the first form (the response is being
    rewritten anyway; the point of the token is identity, not spelling)."""
    tokenized = tok(vault)                                                   # the address, then the same address in upper case
    assert vault.detokenize("s1", "u1", tokenized) == TEXT.replace(EMAIL.upper(), EMAIL)


def test_the_same_value_gets_the_same_token_however_it_is_written(vault):
    tokenized = tok(vault)
    tokens = TOKEN_RE.findall(tokenized)
    emails = [t for t in tokens if t[0] == "EMAIL"]
    assert len(emails) == 2 and emails[0] == emails[1]                      # lower and upper case of one address: one token
    a = tok(vault, "call +91 98765 43210 now", session="p")
    b = tok(vault, "again +91-98765-43210 later", session="p")
    assert TOKEN_RE.search(a).group(0) == TOKEN_RE.search(b).group(0)        # formatting differences do not split one phone number into two


def test_different_values_get_different_tokens(vault):
    t = tok(vault, "a@x.com and b@x.com")
    found = [m.group(0) for m in TOKEN_RE.finditer(t)]
    assert len(found) == 2 and found[0] != found[1]


def test_every_session_has_its_own_nonce_and_tokens_do_not_cross_sessions(vault):
    a = tok(vault, "mail a@x.com", session="A")
    b = tok(vault, "mail a@x.com", session="B")
    assert TOKEN_RE.search(a).group(3) != TOKEN_RE.search(b).group(3)
    assert vault.detokenize("B", "u1", a) == a                              # A's token does not resolve in B
    assert vault.detokenize("A", "u1", a) == "mail a@x.com"


def test_a_forged_token_with_a_guessed_counter_but_no_nonce_does_not_resolve(vault):
    tok(vault, "mail a@x.com", session="A")
    forged = "<<EMAIL_1_000000>>"
    assert vault.detokenize("A", "u1", f"see {forged}") == f"see {forged}"


def test_another_user_id_does_not_get_values_back(vault):
    tokenized = tok(vault, "mail a@x.com", session="A", owner="alice")
    assert vault.detokenize("A", "mallory", tokenized) == tokenized


def test_a_foreign_owner_cannot_add_values_to_someone_elses_session(vault):
    tok(vault, "mail a@x.com", session="A", owner="alice")
    other = tok(vault, "mail c@x.com", session="A", owner="mallory")
    assert other == "mail [REDACTED_EMAIL]"                                  # redacted, not stored under alice's vault


def test_unknown_session_and_text_without_tokens_pass_through(vault):
    assert vault.detokenize("nope", "u", "<<EMAIL_1_abcdef>>") == "<<EMAIL_1_abcdef>>"
    assert vault.detokenize("nope", "u", "plain text") == "plain text"


def test_per_session_cap_falls_back_to_redaction():
    v = PseudonymVault(max_values_per_session=2)
    out = v.tokenize("s", "u", "a@x.com b@x.com c@x.com", spans_of("a@x.com b@x.com c@x.com"))
    assert len(TOKEN_RE.findall(out)) == 2 and out.endswith("[REDACTED_EMAIL]")
    assert v.stats()["values"] == 2


def test_session_cap_evicts_the_oldest():
    v = PseudonymVault(max_sessions=3)
    for i in range(5):
        v.tokenize(f"s{i}", "u", "a@x.com", spans_of("a@x.com"))
    assert v.stats()["sessions"] == 3


def test_ttl_expiry_drops_the_vault():
    v = PseudonymVault(ttl_seconds=0.05)
    out = v.tokenize("s", "u", "a@x.com", spans_of("a@x.com"))
    time.sleep(0.1)
    assert v.detokenize("s", "u", out) == out                                # gone: the token no longer resolves


def test_forget_and_repr_do_not_leak(vault):
    tok(vault, "mail secret.person@x.com", session="A")
    assert "secret.person" not in repr(vault) and "secret.person" not in str(vault.stats())
    vault.forget("A")
    assert vault.stats() == {"sessions": 0, "values": 0}


def test_spans_are_applied_in_text_order_with_untouched_text_between(vault):
    text = "x a@x.com y b@y.com z"
    out = vault.tokenize("s", "u", text, [PIISpan("email", 2, 9), PIISpan("email", 12, 19)])
    assert out.startswith("x <<EMAIL_1_") and " y <<EMAIL_2_" in out and out.endswith(" z")


# ---- the stream detokenizer ------------------------------------------------------------------------------------------------------

def test_a_token_split_at_every_position_is_restored_and_no_partial_token_leaks(vault):
    tokenized = tok(vault, "reply to a@x.com please", session="S")
    want = vault.detokenize("S", "u1", tokenized)
    for cut in range(1, len(tokenized)):
        d = vault.stream_detokenizer("S", "u1")
        first = d.feed(tokenized[:cut])
        assert "<<" not in first or ">>" in first[first.rindex("<<"):], f"partial token emitted when cut at {cut}: {first!r}"
        assert first + d.feed(tokenized[cut:]) + d.flush() == want, cut


def test_a_lone_open_bracket_at_the_end_is_held_until_the_next_chunk(vault):
    tokenized = tok(vault, "x a@x.com", session="S")
    d = vault.stream_detokenizer("S", "u1")
    i = tokenized.index("<<")
    first = d.feed(tokenized[:i + 1])
    assert first == tokenized[:i] == "x "                                    # the "<" is held back
    assert first + d.feed(tokenized[i + 1:]) + d.flush() == "x a@x.com"


def test_text_that_only_looks_like_a_token_start_is_eventually_released(vault):
    d = vault.stream_detokenizer("S", "u1")
    out = d.feed("a << b " + "z" * 60)
    out += d.feed(" done") + d.flush()
    assert out == "a << b " + "z" * 60 + " done"


def test_a_disabled_stream_detokenizer_is_a_pass_through_with_no_hold_back(vault):
    tokenized = tok(vault, "a@x.com", session="S")
    d = vault.stream_detokenizer("S", "u1", enabled=False)
    assert d.feed(tokenized[:6]) == tokenized[:6] and d.feed(tokenized[6:]) == tokenized[6:] and d.flush() == ""


# ---- modes and configuration -------------------------------------------------------------------------------------------------------

def test_mode_defaults_to_redact_and_rejects_unknown_values(monkeypatch):
    monkeypatch.delenv("PII_MODE", raising=False)
    assert pseudonymize.mode() == "redact"
    monkeypatch.setenv("PII_MODE", "bogus")
    with pytest.raises(ValueError):
        pseudonymize.mode()


def test_detokenize_roles_default_and_override(monkeypatch):
    monkeypatch.delenv("PII_DETOKENIZE_ROLES", raising=False)
    assert pseudonymize.detokenize_roles() == {"manager", "admin"}
    monkeypatch.setenv("PII_DETOKENIZE_ROLES", " admin ,, ")
    assert pseudonymize.detokenize_roles() == {"admin"}


# ---- through the middleware ----------------------------------------------------------------------------------------------------------

class Recorder(BackendAdapter):
    """Echoes what it receives and remembers it, so a test can see exactly what the backend was given."""
    name = "recorder"

    def __init__(self):
        self.received = []

    def send(self, prompt, session_id, role="employee", user_id="unknown"):
        self.received.append(prompt)
        return f"Noted: {prompt}"


@pytest.fixture(scope="module")
def mw():
    from gateway.middleware import GatewayMiddleware
    return GatewayMiddleware()


def ask(mw, backend, prompt, role="manager", session="mw1", user="u1"):
    return mw.process(prompt, session_id=session, backend=backend, role=role, user_id=user)


def test_default_mode_redacts_and_nothing_is_restored(mw, monkeypatch):
    monkeypatch.delenv("PII_MODE", raising=False)
    backend = Recorder()
    r = ask(mw, backend, f"Please write to {EMAIL} about the invoice", session="d1")
    assert r.allowed and "[REDACTED_EMAIL]" in r.response_text and EMAIL not in r.response_text and EMAIL not in backend.received[0]


def test_pseudonymize_mode_hides_pii_from_the_backend_and_restores_it_for_a_manager(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    backend = Recorder()
    r = ask(mw, backend, f"Please write to {EMAIL} about the invoice", role="manager", session="p1")
    assert r.allowed
    assert EMAIL not in backend.received[0] and TOKEN_RE.search(backend.received[0])        # the backend only ever saw a token
    assert EMAIL in r.response_text and not TOKEN_RE.search(r.response_text)                  # the manager gets the value back


def test_an_employee_keeps_the_tokens(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    r = ask(mw, Recorder(), f"Please write to {EMAIL} about the invoice", role="employee", session="p2")
    assert r.allowed and EMAIL not in r.response_text and TOKEN_RE.search(r.response_text)


def test_the_same_value_keeps_its_token_across_turns_of_a_session(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    backend = Recorder()
    ask(mw, backend, f"First message about {EMAIL}", role="employee", session="p3")
    ask(mw, backend, f"Second message about {EMAIL.upper()}", role="employee", session="p3")
    assert TOKEN_RE.search(backend.received[0]).group(0) == TOKEN_RE.search(backend.received[1]).group(0)


def test_originals_never_reach_the_audit_log(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    logged = []
    monkeypatch.setattr(mw.logger, "log", lambda rec: logged.append(str(rec)))
    ask(mw, Recorder(), f"Mail {EMAIL}, Aadhaar {AADHAAR}", role="manager", session="p4")
    blob = " ".join(logged)
    assert EMAIL not in blob and AADHAAR not in blob and "aadhaar" in blob        # types are logged, values are not


def test_a_different_user_id_on_the_same_session_does_not_get_values_back(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    backend = Recorder()
    ask(mw, backend, f"Mail {EMAIL}", role="manager", session="p5", user="alice")
    token = TOKEN_RE.search(backend.received[0]).group(0)
    r = ask(mw, backend, f"Repeat this exactly: {token}", role="manager", session="p5", user="mallory")
    assert EMAIL not in (r.response_text or "")


def test_streaming_restores_a_token_split_across_chunks_for_a_manager(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    chunks = [c["chunk"] for c in mw.process_streaming(f"Please write to {EMAIL} about the invoice and the delivery date", session_id="p6",
                                                       backend=Recorder(), role="manager", user_id="u1")]
    joined = "".join(chunks)
    assert EMAIL in joined and not TOKEN_RE.search(joined)
    assert not any(re.search(r"<<[A-Z_]*_?\d*_?[0-9a-f]*$", c) for c in chunks), "a partial token was emitted in a chunk"


def test_streaming_for_an_employee_keeps_whole_tokens_only(mw, monkeypatch):
    monkeypatch.setenv("PII_MODE", "pseudonymize")
    chunks = [c["chunk"] for c in mw.process_streaming(f"Please write to {EMAIL} about the invoice", session_id="p7",
                                                       backend=Recorder(), role="employee", user_id="u1")]
    joined = "".join(chunks)
    assert EMAIL not in joined and TOKEN_RE.search(joined)
