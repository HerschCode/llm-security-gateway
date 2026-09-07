"""
Tier 3: adaptive thresholding. Detection sensitivity adjusts based on a
session's own risk history -- a session that's already triggered blocks looks
more suspicious on its NEXT request too, so thresholds tighten (become more
sensitive) rather than treating every request as independent.

Design: a risk score per session, incremented on each block (pre- or
post-flight), decayed over time so a session that goes quiet eventually
returns to baseline sensitivity rather than staying permanently flagged.
Risk score maps to a threshold multiplier applied to the embedding-similarity
and classifier thresholds -- higher risk -> lower effective threshold ->
easier to trip.

This is deliberately simple (linear decay, linear threshold scaling) --
a real production system might use a proper time-decayed EWMA or a learned
risk model, but the mechanism (session history changes sensitivity) is the
actual Tier-3 ask, not the specific decay function.
"""
import time
from dataclasses import dataclass, field

RISK_INCREMENT_PER_BLOCK = 0.3
RISK_DECAY_PER_SECOND = 0.01     # risk score decays toward 0 over time
RISK_MAX = 1.0

# At risk=0: thresholds unchanged (multiplier=1.0).
# At risk=1.0 (max): thresholds scaled down to 50% of baseline -- much easier to trip.
MIN_THRESHOLD_MULTIPLIER = 0.5


@dataclass
class SessionRisk:
    score: float = 0.0
    last_updated: float = field(default_factory=time.time)


class AdaptiveThresholdTracker:
    """Periodically sweeps sessions whose risk has fully decayed to bound
    memory growth -- same class of issue found and fixed in
    gateway/session_checks.py.SessionTracker, see that fix's comment for the
    full reasoning. Here, "gone quiet" means risk has decayed to (near) zero,
    which -- unlike the timestamp tracker -- only requires checking the
    current score, since decay is continuous rather than window-based."""

    SWEEP_INTERVAL = 100
    DECAYED_THRESHOLD = 1e-6  # treat as fully decayed below this, avoid float dust

    def __init__(self):
        self._risk: dict[str, SessionRisk] = {}
        self._calls_since_sweep = 0

    def _sweep(self):
        stale_ids = [sid for sid in self._risk if self._decay(sid) < self.DECAYED_THRESHOLD]
        for sid in stale_ids:
            del self._risk[sid]

    def _decay(self, session_id: str) -> float:
        risk = self._risk.get(session_id)
        if risk is None:
            return 0.0
        elapsed = time.time() - risk.last_updated
        decayed = max(0.0, risk.score - elapsed * RISK_DECAY_PER_SECOND)
        risk.score = decayed
        risk.last_updated = time.time()
        return decayed

    def record_block(self, session_id: str):
        self._calls_since_sweep += 1
        if self._calls_since_sweep >= self.SWEEP_INTERVAL:
            self._sweep()
            self._calls_since_sweep = 0

        current = self._decay(session_id)
        new_score = min(RISK_MAX, current + RISK_INCREMENT_PER_BLOCK)
        self._risk[session_id] = SessionRisk(score=new_score, last_updated=time.time())

    def get_risk(self, session_id: str) -> float:
        return self._decay(session_id)

    def get_threshold_multiplier(self, session_id: str) -> float:
        """1.0 = baseline sensitivity, down to MIN_THRESHOLD_MULTIPLIER at max risk."""
        risk = self.get_risk(session_id)
        return 1.0 - (1.0 - MIN_THRESHOLD_MULTIPLIER) * risk
