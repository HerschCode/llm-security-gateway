"""
Pre-flight PII detection/redaction. Regex-based on purpose: PII patterns
(emails, phone numbers, SSNs, credit-card-shaped numbers) are structurally
regular, so this is one check where rule-based is the *right* tool, not a
weak stand-in the way it is for injection detection. Redacts in place and
reports what was found, rather than blocking outright -- a message containing
an email address usually isn't an attack, it's normal user content that
shouldn't reach logs/backends unredacted.
"""
import re
from dataclasses import dataclass, field

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


@dataclass
class PIIResult:
    redacted_text: str
    found: list[str] = field(default_factory=list)  # list of PII types found


def scan_and_redact(text: str) -> PIIResult:
    redacted = text
    found = []
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(redacted):
            found.append(pii_type)
            redacted = pattern.sub(f"[REDACTED_{pii_type.upper()}]", redacted)
    return PIIResult(redacted_text=redacted, found=found)
