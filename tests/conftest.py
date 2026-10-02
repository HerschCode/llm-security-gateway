"""Suite-wide pytest fixtures and hooks.

AUTH_MODE selects how the gateway authenticates to operations-assistant (gateway/adapters/upstream_auth.py) and is read on every call, so a value left
in a developer's shell would silently change which code path every adapter test exercises. It is removed before each test; the tests that need a mode
set it themselves.

Under GitHub Actions every failing test is also reported as a workflow annotation (`::error ...`). Annotations show on the run page and are readable
through the public check-runs API without the full log (which needs admin rights), which matters for a failure that only reproduces on the runner
(Linux, Python 3.12, locked dependency versions). Outside Actions the hook below does nothing.
"""
import os

import pytest

# Suppress stdout decision logs during the test suite so pytest's captured
# output stays clean.  Set the env var before any test module imports the
# logger (conftest.py loads first); also directly clear the module-level flag
# in case the module was already imported during collection.
os.environ.setdefault("GATEWAY_LOG_STDOUT", "0")
try:
    import gateway.logging_schema as _ls
    _ls._LOG_STDOUT = False
except ImportError:
    pass


@pytest.fixture(autouse=True)
def _auth_mode_unset(monkeypatch):
    monkeypatch.delenv("AUTH_MODE", raising=False)


_MAX_ANNOTATIONS = 10          # GitHub shows at most 10 error annotations per step
_reported = 0


def _escape(text: str, *, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def pytest_runtest_logreport(report):
    global _reported
    if os.environ.get("GITHUB_ACTIONS") != "true" or not report.failed or _reported >= _MAX_ANNOTATIONS:
        return
    _reported += 1
    path, line, _ = report.location
    detail = (getattr(report, "longreprtext", "") or "")[-1400:]
    print(f"\n::error file={_escape(path, prop=True)},line={(line or 0) + 1},title={_escape('FAILED ' + report.nodeid, prop=True)}::{_escape(detail)}")
