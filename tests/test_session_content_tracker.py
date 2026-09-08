"""Unit tests for SessionContentTracker in isolation -- no middleware, no models."""
from gateway.session_checks import SessionContentTracker


def test_first_turn_has_no_prior_context():
    tracker = SessionContentTracker()
    context = tracker.get_context_text("s1", "hello")
    assert context == "hello"


def test_recorded_turns_appear_in_later_context():
    tracker = SessionContentTracker()
    tracker.record_turn("s1", "turn one")
    tracker.record_turn("s1", "turn two")
    context = tracker.get_context_text("s1", "turn three")
    assert context == "turn one turn two turn three"


def test_sessions_are_isolated():
    tracker = SessionContentTracker()
    tracker.record_turn("s1", "session one's secret turn")
    context = tracker.get_context_text("s2", "hello")
    assert "secret" not in context


def test_context_bounded_to_max_turns():
    tracker = SessionContentTracker(max_turns=3)
    for i in range(5):
        tracker.record_turn("s1", f"turn{i}")
    context = tracker.get_context_text("s1", "current")
    # only the most recent 3 recorded turns should survive
    assert "turn0" not in context
    assert "turn1" not in context
    assert "turn2" in context and "turn3" in context and "turn4" in context


def test_stale_session_context_resets_after_ttl():
    tracker = SessionContentTracker(ttl_seconds=0.05)
    tracker.record_turn("s1", "old turn")
    import time
    time.sleep(0.1)
    context = tracker.get_context_text("s1", "new turn")
    assert context == "new turn"
