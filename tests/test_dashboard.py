"""Tests for gateway/dashboard.py, covering two bugs found during an audit
pass (see docs/decisions.md): a malformed log line crashing compute_stats(),
and an O(total_lines_ever_written) full-file re-read on every poll."""
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.dashboard import _LogTail, compute_stats
from gateway.logging_schema import LOG_PATH


def _rec(sid, decision="allow"):
    return json.dumps({
        "timestamp": time.time(), "session_id": sid, "request_id": "r",
        "phase": "pre_flight", "decision": decision, "detection_layer_used": None,
        "latency_ms": 1.0, "matched_pattern_id": None, "extra": {},
    })


def test_malformed_log_line_does_not_crash_compute_stats():
    """Regression test: a syntactically-valid-JSON line missing required
    fields (decision/phase/timestamp) previously crashed compute_stats()
    with a raw KeyError."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "w") as f:
        f.write(_rec("good-record") + "\n")
        f.write(json.dumps({"timestamp": time.time(), "session_id": "malformed"}) + "\n")
        f.write(_rec("another-good-record", decision="block") + "\n")

    stats = compute_stats()  # should not raise
    assert stats["total_requests_in_window"] == 2


def test_log_tail_reads_incrementally():
    with open(LOG_PATH, "w") as f:
        f.write(_rec("a") + "\n")
        f.write(_rec("b") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 2
    pos_after_first_read = tail._file_pos

    with open(LOG_PATH, "a") as f:
        f.write(_rec("c") + "\n")

    assert len(tail.read_all()) == 3
    assert tail._file_pos > pos_after_first_read


def test_log_tail_does_not_consume_incomplete_final_line():
    with open(LOG_PATH, "w") as f:
        f.write(_rec("a") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 1

    with open(LOG_PATH, "a") as f:
        f.write(_rec("b")[:15])  # no trailing newline -- write "in progress"

    assert len(tail.read_all()) == 1  # incomplete line not consumed yet

    with open(LOG_PATH, "a") as f:
        f.write(_rec("b")[15:] + "\n")

    assert len(tail.read_all()) == 2  # now complete, picked up


def test_log_tail_handles_rotation():
    with open(LOG_PATH, "w") as f:
        f.write(_rec("before-rotation") + "\n")

    tail = _LogTail()
    assert len(tail.read_all()) == 1

    os.remove(LOG_PATH)
    with open(LOG_PATH, "w") as f:
        f.write(_rec("after-rotation") + "\n")

    records = tail.read_all()
    assert len(records) == 1
    assert records[0]["session_id"] == "after-rotation"
