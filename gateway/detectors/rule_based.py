"""
Layer 1: Rule-based prompt-injection detector.

Cheapest, fastest, weakest layer. Keyword/regex matching against known injection
phrases, with Unicode NFKC normalization so obvious homoglyph substitution
(GW-012-style) doesn't trivially dodge it. Still expected to miss paraphrase and
encoding (base64/leetspeak) by design -- that gap is the whole point of having
layers 2 and 3, reported honestly in the comparison table rather than patched
away with ever-more regexes.

Multi-turn-split attacks are a different story since gateway/session_checks.py's
SessionContentTracker started reconstructing session context upstream of every
layer (including this one) -- if a split payload's pieces land adjacent once
reconstructed, this layer's exact-phrase regex genuinely can catch it now (see
tests/test_multi_turn_detection.py). What this layer still can't do is catch a
split payload whose pieces DON'T reconstruct into one of its known phrases
verbatim (a paraphrased or reworded split) -- that remains layer 2/3's job, same
as for a single-turn paraphrase attack.
"""
import re
import time
import unicodedata
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    blocked: bool
    layer: str
    confidence: float           # 0.0-1.0, layer-specific meaning
    matched_pattern_id: str | None
    latency_ms: float
    details: dict = field(default_factory=dict)


# Each pattern gets an ID so blocked requests can log *which* rule fired
# (matches the logging schema's matched_pattern_id field).
PATTERNS = [
    ("RB-001", r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"),
    ("RB-002", r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?"),
    ("RB-003", r"you\s+are\s+now\s+(a|an)\s+\w"),
    ("RB-004", r"\bsystem\s*:\s*"),
    ("RB-005", r"\[?\s*system\s+override\s*\]?"),
    ("RB-006", r"developer\s+mode"),
    ("RB-007", r"jailbreak"),
    ("RB-008", r"pretend\s+you\s+(are|have)\s+no\s+(restrictions|filters|rules)"),
    ("RB-009", r"reveal\s+(your\s+)?system\s+prompt"),
    ("RB-010", r"disable\s+(your\s+)?(content\s+)?filters?"),
    ("RB-011", r"admin(istrator)?[\s\-]?(level\s+)?clearance"),
    ("RB-012", r"skip\s+(the\s+)?(usual\s+)?(safety|role)\s+check"),
    ("RB-013", r"base64[\s\-]?decode"),
    ("RB-014", r"no\s+longer\s+(bound|restricted)\s+by"),
]

_COMPILED = [(pid, re.compile(pattern, re.IGNORECASE)) for pid, pattern in PATTERNS]


def _normalize(text: str) -> str:
    """NFKC normalization collapses many homoglyph/fullwidth tricks to their
    canonical ASCII form. Does NOT catch every Unicode evasion (e.g. some
    Cyrillic homoglyphs normalize to themselves, not to Latin) -- documented
    as a known gap, see corpus case GW-012 and the comparison table notes."""
    return unicodedata.normalize("NFKC", text)


def detect(text: str) -> DetectionResult:
    start = time.perf_counter()
    normalized = _normalize(text)

    for pattern_id, compiled in _COMPILED:
        if compiled.search(normalized):
            latency_ms = (time.perf_counter() - start) * 1000
            return DetectionResult(
                blocked=True,
                layer="rule_based",
                confidence=1.0,
                matched_pattern_id=pattern_id,
                latency_ms=latency_ms,
                details={"matched_text_snippet": compiled.search(normalized).group(0)},
            )

    latency_ms = (time.perf_counter() - start) * 1000
    return DetectionResult(
        blocked=False,
        layer="rule_based",
        confidence=0.0,
        matched_pattern_id=None,
        latency_ms=latency_ms,
        details={},
    )
