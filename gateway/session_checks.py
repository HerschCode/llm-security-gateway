"""
Pre-flight session-level checks: rate limiting, behavior anomaly detection, and
(SessionContentTracker, below) real multi-turn message-content tracking.

All in-memory / process-local by design -- this is a portfolio project, not a
production service, so no Redis/shared-state dependency. Documented as a known
scaling limitation (multi-instance deployment would need a shared session
store) rather than silently pretending it's production-ready.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 20

# Anomaly: flag if request rate in the last ANOMALY_WINDOW_SECONDS exceeds
# ANOMALY_SPIKE_MULTIPLIER times the session's historical average rate.
ANOMALY_WINDOW_SECONDS = 10
ANOMALY_MIN_HISTORY = 5
ANOMALY_SPIKE_MULTIPLIER = 4


@dataclass
class SessionCheckResult:
    allowed: bool
    reason: str | None
    details: dict = field(default_factory=dict)


class SessionTracker:
    """One instance per gateway process. Tracks per-session request timestamps
    for both rate limiting and anomaly detection off the same underlying data.

    Periodically sweeps sessions with empty timestamp deques (all entries
    aged out of the rate-limit window) to bound memory growth -- found via
    audit: this dict previously had NO eviction at all, so every unique
    session_id ever seen stayed in memory for the lifetime of the process.
    For a long-running gateway seeing many short-lived sessions (the normal
    case), that's an unbounded memory leak, not just a "no shared store"
    scaling limitation. Sweeping every SWEEP_INTERVAL calls rather than on
    every call keeps the check itself cheap."""

    SWEEP_INTERVAL = 100

    def __init__(self):
        self._timestamps: dict[str, deque] = defaultdict(deque)
        self._calls_since_sweep = 0

    def _sweep(self):
        """Evicts sessions whose entire timestamp history is already outside
        the rate-limit window -- i.e. sessions that have gone quiet. Checking
        only the deque's newest entry (history[-1]) is enough: if even the
        most recent request is stale, everything before it is too.
        Deliberately does NOT just check for already-empty deques -- a
        session that sent a few requests and then went silent forever keeps
        a non-empty deque of increasingly stale timestamps indefinitely,
        since trimming (the `while` loop in record_and_check) only runs when
        a NEW request arrives for that specific session. An earlier version
        of this method only removed empty deques and would have missed this
        exact case, which is the actual common leak scenario, not an edge
        case."""
        now = time.time()
        stale_ids = [
            sid for sid, history in self._timestamps.items()
            if not history or now - history[-1] > RATE_LIMIT_WINDOW_SECONDS
        ]
        for sid in stale_ids:
            del self._timestamps[sid]

    def record_and_check(self, session_id: str) -> SessionCheckResult:
        self._calls_since_sweep += 1
        if self._calls_since_sweep >= self.SWEEP_INTERVAL:
            self._sweep()
            self._calls_since_sweep = 0

        now = time.time()
        history = self._timestamps[session_id]
        history.append(now)

        # Rate limit check: count requests in the rate-limit window.
        while history and now - history[0] > RATE_LIMIT_WINDOW_SECONDS:
            history.popleft()

        if len(history) > RATE_LIMIT_MAX_REQUESTS:
            return SessionCheckResult(
                allowed=False,
                reason="rate_limit_exceeded",
                details={"requests_in_window": len(history), "window_seconds": RATE_LIMIT_WINDOW_SECONDS},
            )

        # Anomaly check: only meaningful once we have enough history to judge
        # a "normal" rate for this session.
        if len(history) >= ANOMALY_MIN_HISTORY:
            session_duration_actual = now - history[0]

            # Absolute burst check for brand-new sessions -- found via audit:
            # a session that fires ANOMALY_MIN_HISTORY+ requests within its
            # own first ANOMALY_WINDOW_SECONDS was completely undetected by
            # the ratio-based check below. Root cause: that check compares
            # the recent rate against the session's OWN historical rate, but
            # a session still within its first ANOMALY_WINDOW_SECONDS has no
            # real history yet -- the max(session_duration, 1.0) clamp a few
            # lines down makes an immediate flood look "normal relative to
            # itself," since there's nothing slower in its (nonexistent)
            # history to compare against. Verified empirically: 10 requests
            # fired back-to-back at session start were all allowed before
            # this fix. This check catches that specific blind spot directly
            # rather than trying to patch the ratio math to cover it.
            if session_duration_actual <= ANOMALY_WINDOW_SECONDS:
                # TRADE-OFF, STATED PLAINLY: this has no way to distinguish a
                # malicious burst from a legitimate one -- e.g. a dashboard
                # or UI that fires several requests in quick succession on
                # load, within the same session, would be flagged too. Fixing
                # the blind spot this check closes necessarily costs some
                # precision on legitimate rapid-fire usage; not treated as a
                # free win. If false positives on legitimate bursts turn out
                # to matter in practice, the right next step is distinguishing
                # request *content* (same question repeated vs. varied
                # requests) rather than just count, which this check doesn't
                # attempt.
                return SessionCheckResult(
                    allowed=False,
                    reason="session_anomaly_burst_at_start",
                    details={"requests": len(history), "elapsed_seconds": round(session_duration_actual, 3)},
                )

            recent_count = sum(1 for t in history if now - t <= ANOMALY_WINDOW_SECONDS)
            session_duration = max(session_duration_actual, 1.0)
            historical_rate_per_10s = (len(history) / session_duration) * ANOMALY_WINDOW_SECONDS
            recent_rate = recent_count

            if historical_rate_per_10s > 0 and recent_rate > historical_rate_per_10s * ANOMALY_SPIKE_MULTIPLIER:
                return SessionCheckResult(
                    allowed=False,
                    reason="session_anomaly_spike",
                    details={
                        "recent_rate_per_10s": recent_rate,
                        "historical_rate_per_10s": round(historical_rate_per_10s, 2),
                    },
                )

        return SessionCheckResult(allowed=True, reason=None, details={"requests_in_window": len(history)})


# How many prior turns (this session's own past messages, post-PII-redaction) get
# reconstructed alongside the current message before running injection detection.
# Bounded rather than unbounded session history for two reasons: memory (same
# eviction discipline as SessionTracker above) and detection quality -- an
# unbounded window would eventually make every session's context so long that a
# short, clearly-benign new message gets buried in noise the detectors weren't
# tuned against.
MULTI_TURN_CONTEXT_TURNS = 5
MULTI_TURN_TTL_SECONDS = 600  # a session that's gone quiet for 10 min starts fresh


class SessionContentTracker:
    """Closes the gap README.md names explicitly: "Multi-turn detection tests
    concatenated transcripts as one message, not true per-turn/session-context
    chaining." Before this, gateway/middleware.py's process() only ever inspected
    the CURRENT message in isolation -- a GW-009-style attack (splitting a
    malicious instruction across several individually-innocuous turns) was
    structurally undetectable in real per-request usage; the only way the corpus
    "tested" it was by pre-concatenating the whole fake transcript into one
    string and sending that as a single message, which doesn't exercise this
    project's actual real-time detection path at all.

    Stores each session's recent message TEXT (not just timestamps, unlike
    SessionTracker) so a new message can be checked against the reconstructed
    recent context, not just itself. record_turn() is called only for messages
    that passed pre-flight (see middleware.py) -- an already-blocked message
    shouldn't get added to context future turns are judged against."""

    def __init__(self, max_turns: int = MULTI_TURN_CONTEXT_TURNS, ttl_seconds: float = MULTI_TURN_TTL_SECONDS):
        self._turns: dict[str, deque] = defaultdict(lambda: deque(maxlen=max_turns))
        self._last_seen: dict[str, float] = {}
        self.ttl_seconds = ttl_seconds
        self._calls_since_sweep = 0
        self.SWEEP_INTERVAL = 100

    def _sweep(self, now: float):
        stale_ids = [sid for sid, last in self._last_seen.items() if now - last > self.ttl_seconds]
        for sid in stale_ids:
            self._turns.pop(sid, None)
            self._last_seen.pop(sid, None)

    def get_context_text(self, session_id: str, current_message: str) -> str:
        """Recent prior turns (oldest first) followed by the current message,
        joined into one string for detection -- NOT what gets forwarded to the
        backend (middleware.py still sends only the real current message there);
        this reconstructed text exists purely so the injection detectors can see
        what a real multi-turn conversation actually looked like."""
        now = time.time()
        if now - self._last_seen.get(session_id, 0) > self.ttl_seconds:
            self._turns.pop(session_id, None)  # session gone quiet long enough -- start fresh, no stale context
        prior_turns = list(self._turns.get(session_id, []))
        return " ".join(prior_turns + [current_message])

    def record_turn(self, session_id: str, message: str):
        now = time.time()
        self._calls_since_sweep += 1
        if self._calls_since_sweep >= self.SWEEP_INTERVAL:
            self._sweep(now)
            self._calls_since_sweep = 0

        self._turns[session_id].append(message)
        self._last_seen[session_id] = now
