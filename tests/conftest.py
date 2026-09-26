"""Suite-wide pytest hooks.

Under GitHub Actions every failing test is also reported as a workflow annotation (`::error ...`). Annotations show on the run page and are readable through the
public check-runs API without the full log (which needs admin rights), which matters for a failure that only reproduces on the runner (Linux, Python 3.12, locked
dependency versions). Outside Actions this file does nothing.
"""
import os

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
