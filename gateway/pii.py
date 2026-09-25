"""
Pre-flight PII detection/redaction. Regex-based by default, on purpose: PII patterns
(emails, phone numbers, SSNs, credit-card-shaped numbers) are structurally
regular, so this is one check where rule-based is the *right* tool, not a
weak stand-in the way it is for injection detection. Redacts in place and
reports what was found, rather than blocking outright -- a message containing
an email address usually isn't an attack, it's normal user content that
shouldn't reach logs/backends unredacted.

Tightened after the 2026-09 red-team pass (RT-09 in reports/redteam-2026-09.md): the original phone and card patterns matched
any 10-16 digit run, so an order number such as 4500012345 was redacted to [REDACTED_PHONE] before the backend ever saw it.
A phone number now needs separators (or a leading +), and a card number must pass the Luhn checksum.

Backends (PII_BACKEND, read on every call):
  regex          the default: US-format patterns with the SSA validity rules for SSNs, plus the dependency-free Indian identifiers of
                 gateway/pii_in.py (Aadhaar with the Verhoeff checksum, PAN, Indian mobile/landline numbers), each gated so that order numbers
                 are not redacted.
  regex_us       the pre-Phase-5 patterns only (kept so the evaluation can compare against exactly what used to ship).
  presidio       Microsoft Presidio's pattern recognizers plus custom Indian recognizers (optional extra `[pii]`).
  presidio_ner   the same plus a spaCy model, which adds PERSON names (a larger dependency; not for the 512 MB tier).
Measured in scripts/evaluate_pii.py; the numbers and the decision are in docs/pii-evaluation.md.

Every backend returns spans, so redaction and pseudonymization (gateway/pseudonymize.py) share one code path.
"""
import os
import re
from dataclasses import dataclass, field

from gateway import pii_in

US_PATTERNS = {
    # The lookbehind keeps a match from STARTING inside a run of local-part characters. Without it the engine rescans the whole run from every
    # position when there is no "@" after it: 270 ms for 20,000 characters of plain "a" (quadratic; SEC-02, docs/security-scans.md).
    "email": re.compile(r"(?<![a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    # Separators (or a leading +) are REQUIRED: ten bare digits are far more often an order or case number than a phone number.
    "phone": re.compile(r"(?<![\w-])(?:(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}|\+\d{10,14})(?![\w-])"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    # Candidates only (13-19 digits, optional single spaces or dashes); confirmed by a Luhn check.
    "credit_card": re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])"),
}
PII_PATTERNS = US_PATTERNS          # the name earlier code used

# When two spans overlap, the more specific validator wins.
PRIORITY = ["email", "credit_card", "aadhaar", "ssn", "pan", "phone", "person"]


@dataclass(frozen=True)
class PIISpan:
    type: str          # email | phone | ssn | credit_card | aadhaar | pan | person
    start: int
    end: int
    score: float = 1.0
    source: str = "regex"


@dataclass
class PIIResult:
    redacted_text: str
    found: list[str] = field(default_factory=list)          # PII types found, in order of first appearance
    spans: list[PIISpan] = field(default_factory=list)


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _ssn_ok(candidate: str) -> bool:
    """The SSA's own validity rules: no area 000, 666 or 900-999, no group 00, no serial 0000. Such a number cannot be a real SSN."""
    area, group, serial = candidate.split("-")
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def detect_spans_regex(text: str, extended: bool = True) -> list[PIISpan]:
    """`extended=False` is exactly what shipped before Phase 5 (US formats, Luhn-checked cards). `extended=True` adds the SSA validity rules
    for SSNs and the Indian identifiers of gateway/pii_in.py."""
    spans = []
    for pii_type, pattern in US_PATTERNS.items():
        for m in pattern.finditer(text):
            if pii_type == "credit_card" and not _luhn_ok(m.group()):
                continue
            if pii_type == "ssn" and extended and not _ssn_ok(m.group()):
                continue
            spans.append(PIISpan(pii_type, m.start(), m.end()))
    if extended:
        for start, end, score, _ in pii_in.find_aadhaar(text):
            spans.append(PIISpan("aadhaar", start, end, score))
        for start, end, score, _ in pii_in.find_pan(text):
            spans.append(PIISpan("pan", start, end, score))
        for start, end, score, _ in pii_in.find_phone(text):
            spans.append(PIISpan("phone", start, end, score))
    return spans


def resolve_overlaps(spans: list[PIISpan]) -> list[PIISpan]:
    """Non-overlapping spans in text order. Where spans overlap the one whose type ranks higher in PRIORITY wins; ties go to the longer span."""
    rank = {t: i for i, t in enumerate(PRIORITY)}
    kept: list[PIISpan] = []
    for s in sorted(spans, key=lambda s: (rank.get(s.type, len(rank)), -(s.end - s.start), s.start)):
        if not any(s.start < k.end and k.start < s.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)


def detect_spans(text: str) -> list[PIISpan]:
    backend = os.environ.get("PII_BACKEND", "regex")
    if backend == "regex":
        spans = detect_spans_regex(text)
    elif backend == "regex_us":
        spans = detect_spans_regex(text, extended=False)
    elif backend in ("presidio", "presidio_ner"):
        from gateway.pii_presidio import detect_spans_presidio          # optional extra: imported only when selected
        spans = detect_spans_presidio(text, ner=backend == "presidio_ner")
    else:
        raise ValueError(f"PII_BACKEND must be regex, regex_us, presidio or presidio_ner, got {backend!r}")
    return resolve_overlaps(spans)


def redact(text: str, spans: list[PIISpan]) -> str:
    out, pos = [], 0
    for s in spans:
        out.append(text[pos:s.start])
        out.append(f"[REDACTED_{s.type.upper()}]")
        pos = s.end
    out.append(text[pos:])
    return "".join(out)


def scan_and_redact(text: str) -> PIIResult:
    spans = detect_spans(text)
    found: list[str] = []
    for s in spans:
        if s.type not in found:
            found.append(s.type)
    return PIIResult(redacted_text=redact(text, spans), found=found, spans=spans)
