"""The gateway logger must not keep the log file open between writes.

Found via tests/test_dashboard.py::test_log_tail_handles_rotation failing with PermissionError on Windows: GatewayLogger opened
logs/gateway.jsonl once and held the handle for its whole life. On Windows a file opened that way cannot be renamed or deleted by anyone
else (WinError 32), so log rotation was impossible while the gateway ran; on Linux the rename works but the logger keeps writing to the
rotated file. The logger now opens, writes a batch and closes, so the file can be rotated between batches on every platform."""
import json
import os
import threading
import time

import pytest

from gateway import logging_schema
from gateway.logging_schema import GatewayLogger, LogRecord


def record(sid):
    return LogRecord(timestamp=time.time(), session_id=sid, request_id="r", phase="pre_flight", decision="allow",
                     detection_layer_used=None, latency_ms=1.0, matched_pattern_id=None)


def lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def test_a_running_logger_does_not_block_rotation(tmp_path):
    path = tmp_path / "gateway.jsonl"
    lg = GatewayLogger(path)
    lg.log(record("before"))
    assert wait_for(lambda: len(lines(path)) == 1)

    rotated = tmp_path / "gateway.jsonl.1"
    os.replace(path, rotated)                     # PermissionError [WinError 32] while the logger held the file open

    lg.log(record("after"))
    assert wait_for(lambda: len(lines(path)) == 1)
    assert [r["session_id"] for r in lines(rotated)] == ["before"]     # the rotated file is not written to any more
    assert [r["session_id"] for r in lines(path)] == ["after"]         # a fresh file was started
    lg.close()


def test_a_running_logger_does_not_block_deleting_the_log(tmp_path):
    path = tmp_path / "gateway.jsonl"
    lg = GatewayLogger(path)
    lg.log(record("a"))
    assert wait_for(lambda: len(lines(path)) == 1)
    os.remove(path)
    lg.log(record("b"))
    assert wait_for(lambda: [r["session_id"] for r in lines(path)] == ["b"])
    lg.close()


def test_close_flushes_everything_that_was_queued(tmp_path):
    path = tmp_path / "gateway.jsonl"
    lg = GatewayLogger(path)
    for i in range(500):
        lg.log(record(f"s{i}"))
    lg.close()
    assert [r["session_id"] for r in lines(path)] == [f"s{i}" for i in range(500)]


def test_concurrent_writers_lose_nothing_and_keep_order_per_thread(tmp_path):
    path = tmp_path / "gateway.jsonl"
    lg = GatewayLogger(path)

    def work(t):
        for i in range(100):
            lg.log(record(f"t{t}-{i}"))

    threads = [threading.Thread(target=work, args=(t,)) for t in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    lg.close()
    ids = [r["session_id"] for r in lines(path)]
    assert len(ids) == 800 and len(set(ids)) == 800
    for t in range(8):
        mine = [int(x.split("-")[1]) for x in ids if x.startswith(f"t{t}-")]
        assert mine == sorted(mine)


def test_the_directory_is_created_if_it_is_missing_at_write_time(tmp_path):
    path = tmp_path / "nested" / "deeper" / "gateway.jsonl"
    lg = GatewayLogger(path)
    lg.log(record("x"))
    lg.close()
    assert [r["session_id"] for r in lines(path)] == ["x"]


def test_a_transient_permission_error_is_retried(tmp_path, monkeypatch):
    """A rotator can hold the file for an instant on Windows; the batch must not be lost and the writer must not die."""
    path = tmp_path / "gateway.jsonl"
    real_open = open
    failures = {"left": 2}

    def flaky_open(file, *a, **k):
        if str(file) == str(path) and failures["left"] > 0:
            failures["left"] -= 1
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real_open(file, *a, **k)

    monkeypatch.setattr(logging_schema, "open", flaky_open, raising=False)
    lg = GatewayLogger(path)
    lg.log(record("kept"))
    lg.close()
    assert [r["session_id"] for r in lines(path)] == ["kept"] and failures["left"] == 0


def test_a_persistent_failure_drops_the_batch_but_the_writer_survives(tmp_path, monkeypatch):
    path = tmp_path / "gateway.jsonl"
    real_open = open
    state = {"fail": True}

    def blocked_open(file, *a, **k):
        if str(file) == str(path) and state["fail"]:
            raise PermissionError(13, "locked")
        return real_open(file, *a, **k)

    monkeypatch.setattr(logging_schema, "open", blocked_open, raising=False)
    monkeypatch.setattr(logging_schema.time, "sleep", lambda s: None)          # do not actually wait out the retries
    lg = GatewayLogger(path)
    lg.log(record("lost"))
    assert wait_for(lambda: lg.dropped == 1)
    state["fail"] = False
    lg.log(record("later"))
    lg.close()
    assert [r["session_id"] for r in lines(path)] == ["later"]


@pytest.mark.skipif(os.name != "nt", reason="the share-mode restriction that motivated this exists on Windows only")
def test_windows_regression_the_old_pattern_really_blocks_rotation(tmp_path):
    """Documents the platform behaviour the fix works around: a plain open() handle blocks os.replace on Windows."""
    path = tmp_path / "held.jsonl"
    with open(path, "a", encoding="utf-8"):
        with pytest.raises(PermissionError):
            os.replace(path, tmp_path / "held.jsonl.1")
