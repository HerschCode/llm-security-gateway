"""
Pre-flight PII detection/redaction. Regex-based on purpose: PII patterns
(emails, phone numbers, SSNs, credit-card-shaped numbers) are structurally
regular, so this is one check where rule-based is the *right* tool, not a
weak stand-in the way it is for injection detection. Redacts in place and
reports what was found, rather than blocking outright -- a message containing
an email address usually isn't an attack, it's normal user content that
shouldn't reach logs/backends unredacted.

Tightened after the 2026-09 red-team pass (RT-09 in reports/redteam-2026-09.md): the original phone and card patterns matched
any 10-16 digit run, so an order number such as 4500012345 was redacted to [REDACTED_PHONE] before the backend ever saw it.
A phone number now needs separators (or a leading +), and a card number must pass the Luhn checksum. This remains
US-format and regex-only; Indian identifiers and names are the job of the Presidio phase.
"""
import re
from dataclasses import dataclass, field

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    # Separators (or a leading +) are REQUIRED: ten bare digits are far more often an order or case number than a phone number.
    "phone": re.compile(r"(?<![\w-])(?:(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}|\+\d{10,14})(?![\w-])"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    # Candidates only (13-19 digits, optional single spaces or dashes); confirmed by a Luhn check in scan_and_redact.
    "credit_card": re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])"),
}


@dataclass
class PIIResult:
    redacted_text: str
    found: list[str] = field(default_factory=list)  # list of PII types found


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


def scan_and_redact(text: str) -> PIIResult:
    redacted = text
    found = []
    for pii_type, pattern in PII_PATTERNS.items():
        if pii_type == "credit_card":
            hit = False

            def _card(m: re.Match) -> str:
                nonlocal hit
                if _luhn_ok(m.group()):
                    hit = True
                    return "[REDACTED_CREDIT_CARD]"
                return m.group()

            redacted = pattern.sub(_card, redacted)
            if hit:
                found.append(pii_type)
        elif pattern.search(redacted):
            found.append(pii_type)
            redacted = pattern.sub(f"[REDACTED_{pii_type.upper()}]", redacted)
    return PIIResult(redacted_text=redacted, found=found)
