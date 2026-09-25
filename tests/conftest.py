"""Fixtures shared by the whole suite.

AUTH_MODE selects how the gateway authenticates to operations-assistant
(gateway/adapters/upstream_auth.py) and is read on every call, so a value left in a developer's
shell would silently change which code path every adapter test exercises. It is removed before
each test; the tests that need a mode set it themselves.
"""
import pytest


@pytest.fixture(autouse=True)
def _auth_mode_unset(monkeypatch):
    monkeypatch.delenv("AUTH_MODE", raising=False)
