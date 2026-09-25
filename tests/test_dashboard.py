"""Tests for gateway/dashboard.py, covering two bugs found during an audit
pass (see docs/decisions.md): a malformed log line crashing compute_stats(),
and an O(total_lines_ever_written) full-file re-read on every poll.

Every test gets its own log file and its own tail state (the `log` fixture). These tests used to write to the real logs/gateway.jsonl
and share one global tail, which made them depend on test order and on whatever else had that file open; on Windows a file held open
by any other handle cannot be deleted, so test_log_tail_handles_rotation failed with PermissionError. The real cause was in the
logger (it kept a handle open for its whole life) and is fixed there: see tests/test_log_rotation.py."""
import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import gateway.dashboard as dashboard  # noqa: E402
from gateway.dashboard import _LogTail, compute_stats  # noqa: E402
from gateway.logging_schema import GatewayLogger, LogRecord  # noqa: E402


@pytest.fixture(autouse=True)
def log(tmp_path, monkeypatch):
    path = tmp_path / "gateway.jsonl"
    monkeypatch.setattr(dashboard, "LOG_PATH", path)
    monkeypatch.setattr(dashboard, "_log_tail", _LogTail())
    return path


def _rec(sid, decision="allow"):
    return json.dumps({
        "timestamp": time.time(), "session_id": sid, "request_id": "r",
        "phase": "pre_flight", "decision": decision, "detection_layer_used": None,
        "latency_ms": 1.0, "matched_pattern_id": None, "extra": {},
    })


def test_malformed_log_line_does_not_crash_compute_stats(log):
    """Regression test: a syntactically-valid-JSON line missing required
    fields (decision/phase/timestamp) previously crashed compute_stats()
    with a raw KeyError."""
    with open(log, "w") as f:
        f.write(_rec("good-record") + "\n")
        f.write(json.dumps({"timestamp": time.time(), "session_id": "malformed"}) + "\n")
        f.write(_rec("another-good-record", decision="block") + "\n")

    stats = compute_stats()  # should not raise
    assert stats["total_requests_in_window"] == 2


def test_log_tail_reads_incrementally(log):
    with open(log, "w") as f:
        f.write(_rec("a") + "\n")
        f.write(_rec("b") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 2
    pos_after_first_read = tail._file_pos

    with open(log, "a") as f:
        f.write(_rec("c") + "\n")

    assert len(tail.read_all()) == 3
    assert tail._file_pos > pos_after_first_read


def test_log_tail_does_not_consume_incomplete_final_line(log):
    with open(log, "w") as f:
        f.write(_rec("a") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 1

    with open(log, "a") as f:
        f.write(_rec("b")[:15])  # no trailing newline -- write "in progress"

    assert len(tail.read_all()) == 1  # incomplete line not consumed yet

    with open(log, "a") as f:
        f.write(_rec("b")[15:] + "\n")

    assert len(tail.read_all()) == 2  # now complete, picked up


def test_log_tail_handles_rotation(log):
    """Rotation by delete-and-recreate. The test holds no handle on the file when it removes it (a handle held by anything else is what
    makes os.remove fail on Windows), so this is deterministic on every platform."""
    with open(log, "w") as f:
        f.write(_rec("before-rotation") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 1

    os.remove(log)
    with open(log, "w") as f:
        f.write(_rec("after-rotation") + "\n")

    records = tail.read_all()
    assert len(records) == 1
    assert records[0]["session_id"] == "after-rotation"


def test_log_tail_handles_rename_rotation(log):
    """The usual production rotation: the file is renamed away and a new one starts. The new file may well be LONGER than the old offset,
    so only the inode/identity change tells the tail to start over."""
    with open(log, "w") as f:
        f.write(_rec("old-1") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 1

    os.replace(log, log.with_suffix(".jsonl.1"))
    with open(log, "w") as f:
        for i in range(5):
            f.write(_rec(f"new-{i}") + "\n")

    assert [r["session_id"] for r in tail.read_all()] == [f"new-{i}" for i in range(5)]


def test_dashboard_follows_a_live_logger_across_rotation(log):
    """End to end: a running GatewayLogger, the tail reading it, and a rotation in between. Before the logger stopped holding the file
    open this could not even be attempted on Windows."""
    logger = GatewayLogger(log)

    def emit(sid):
        logger.log(LogRecord(timestamp=time.time(), session_id=sid, request_id="r", phase="pre_flight", decision="allow",
                             detection_layer_used=None, latency_ms=1.0, matched_pattern_id=None))

    def wait_for(n, tail):
        end = time.time() + 5
        while time.time() < end and len(tail.read_all()) != n:
            time.sleep(0.01)
        return [r["session_id"] for r in tail.read_all()]

    tail = _LogTail()
    emit("a")
    emit("b")
    assert wait_for(2, tail) == ["a", "b"]

    os.replace(log, log.with_suffix(".jsonl.1"))                # rotate while the logger is alive
    emit("c")
    assert wait_for(1, tail) == ["c"]
    logger.close()


def test_log_tail_detects_truncate_in_place_even_if_the_new_file_is_larger(log):
    """copytruncate-style rotation keeps the same inode, and if more is written than the old offset before the next poll the file did
    not shrink either: neither the inode nor the size gives it away. The tail must notice the content at the start of the file changed."""
    with open(log, "w") as f:
        f.write(_rec("old-1") + "\n")
    tail = _LogTail()
    assert [r["session_id"] for r in tail.read_all()] == ["old-1"]

    with open(log, "w") as f:                                    # same inode, truncated, then refilled with MORE than before
        for i in range(5):
            f.write(_rec(f"new-{i}") + "\n")

    assert [r["session_id"] for r in tail.read_all()] == [f"new-{i}" for i in range(5)]


def test_appending_does_not_look_like_rotation(log):
    """The head of an append-only file never changes, so growth must not trigger a reset (which would re-read the whole log)."""
    with open(log, "w") as f:
        f.write(_rec("a") + "\n")
    tail = _LogTail()
    tail.read_all()
    for i in range(3):
        with open(log, "a") as f:
            f.write(_rec(f"b{i}") + "\n")
        tail.read_all()
    assert [r["session_id"] for r in tail.read_all()] == ["a", "b0", "b1", "b2"]
    assert tail._resets == 0
