"""Tests for gateway/session_checks.py and gateway/adaptive_threshold.py,
including regression tests for two bugs found during an audit pass (see
docs/decisions.md): the burst-at-session-start blind spot in anomaly
detection, and unbounded memory growth in both trackers."""
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.session_checks import SessionTracker, RATE_LIMIT_WINDOW_SECONDS, ANOMALY_MIN_HISTORY, ANOMALY_WINDOW_SECONDS
from gateway.adaptive_threshold import AdaptiveThresholdTracker


def test_normal_paced_requests_are_allowed():
    """Uses one strategic sleep (rather than pacing every request slowly) to
    push the session's elapsed duration past ANOMALY_WINDOW_SECONDS before
    the 5th request, which is what actually matters for avoiding the
    burst-at-start check -- keeps this test's runtime reasonable while still
    testing a genuinely non-bursty pattern, not just "fast but spread out
    just enough to dodge one specific check."""
    tracker = SessionTracker()
    assert tracker.record_and_check("normal-session").allowed
    time.sleep(ANOMALY_WINDOW_SECONDS + 0.1)
    for _ in range(4):
        result = tracker.record_and_check("normal-session")
        assert result.allowed


def test_rate_limit_blocks_excessive_requests():
    tracker = SessionTracker()
    sid = "rate-limit-test"
    results = [tracker.record_and_check(sid) for _ in range(25)]
    assert any(not r.allowed and r.reason == "rate_limit_exceeded" for r in results)


def test_burst_at_session_start_is_caught():
    """Regression test for a real bug found during an audit pass: a session
    firing ANOMALY_MIN_HISTORY+ requests within its own first
    ANOMALY_WINDOW_SECONDS was completely undetected before this fix, because
    the ratio-based anomaly check compares against the session's OWN history,
    which doesn't exist yet for a brand-new session. See
    gateway/session_checks.py's comment on this exact check for the full
    reasoning."""
    tracker = SessionTracker()
    sid = "burst-attack"
    results = [tracker.record_and_check(sid) for _ in range(ANOMALY_MIN_HISTORY + 3)]
    blocked = [r for r in results if not r.allowed]
    assert blocked, "burst at session start should have been caught, but nothing was blocked"
    assert all(r.reason == "session_anomaly_burst_at_start" for r in blocked)


def test_session_tracker_evicts_stale_sessions():
    """Regression test for unbounded memory growth found during an audit
    pass: SessionTracker previously never removed any session_id it had ever
    seen. Verifies sessions with fully-expired timestamp windows are swept."""
    tracker = SessionTracker()
    for i in range(150):
        tracker.record_and_check(f"one-shot-{i}")

    # Force every tracked timestamp far into the past, then trigger enough
    # new calls to cross the sweep interval.
    old_time = time.time() - (RATE_LIMIT_WINDOW_SECONDS + 5)
    for history in tracker._timestamps.values():
        for idx in range(len(history)):
            history[idx] = old_time

    for i in range(tracker.SWEEP_INTERVAL):
        tracker.record_and_check(f"fresh-{i}")

    # The 150 stale one-shot sessions should be gone; only fresh ones remain
    # (plus possibly a couple still accumulating toward the next sweep).
    assert len(tracker._timestamps) <= tracker.SWEEP_INTERVAL + 5


def test_adaptive_tracker_evicts_fully_decayed_sessions():
    """Regression test for the same class of unbounded-growth bug in
    AdaptiveThresholdTracker."""
    tracker = AdaptiveThresholdTracker()
    for i in range(150):
        tracker.record_block(f"blocked-once-{i}")

    for risk in tracker._risk.values():
        risk.last_updated = time.time() - 1000  # force full decay

    for i in range(tracker.SWEEP_INTERVAL):
        tracker.record_block(f"fresh-block-{i}")

    assert len(tracker._risk) <= tracker.SWEEP_INTERVAL + 5


def test_adaptive_tracker_risk_increases_on_block():
    tracker = AdaptiveThresholdTracker()
    sid = "risk-test"
    assert tracker.get_risk(sid) == 0.0
    tracker.record_block(sid)
    assert tracker.get_risk(sid) > 0.0


def test_adaptive_tracker_multiplier_decreases_with_risk():
    tracker = AdaptiveThresholdTracker()
    sid = "multiplier-test"
    baseline = tracker.get_threshold_multiplier(sid)
    tracker.record_block(sid)
    tracker.record_block(sid)
    after_blocks = tracker.get_threshold_multiplier(sid)
    assert after_blocks < baseline
