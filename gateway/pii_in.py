"""
Indian personal identifiers, with no dependencies: Aadhaar (Verhoeff checksum), PAN, and mobile/landline numbers.

The design constraint is the one the RT-09 finding taught (reports/redteam-2026-09.md): an identifier-shaped number is far more often an
order, invoice or tracking number than personal data, and redacting those breaks ordinary requests before the backend sees them. So each
identifier needs more than its digit pattern:

  Aadhaar   12 digits, first digit 2-9. Redacted when it is written in the usual 4-4-4 grouping AND its Verhoeff check digit is valid,
            or when a context word ("aadhaar", "uid", ...) is nearby (then the checksum is not required: people mistype, and test
            numbers are rarely valid). A bare 12-digit run with neither is left alone: about 8% of random 12-digit numbers pass the
            checksum, and timestamps and tracking numbers are 12 digits long.
  PAN       AAAAA9999A (five letters, four digits, a letter) whose fourth letter is one of the ten holder-status codes. Upper case needs
            no context; lower or mixed case needs a nearby "PAN" / "permanent account" context.
  Phone     a mobile number starts with 6-9 and has 10 digits. Redacted with a +91 / 91 / 0 prefix, or in the 5-5 grouping, or bare when a
            context word ("mobile", "phone", "whatsapp", ...) is nearby. STD landlines need the leading 0 and a separator.

Each detector returns (start, end, score, detail) tuples; gateway/pii.py turns them into spans. Measured against the current regex and
Presidio in scripts/evaluate_pii.py (docs/pii-evaluation.md).
"""
import re

# ---- Verhoeff checksum (the check digit scheme UIDAI uses for the last digit of an Aadhaar number) -------------------------------
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_ok(digits: str) -> bool:
    """True if the digit string, check digit included, satisfies the Verhoeff checksum."""
    if not digits.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(payload: str) -> int:
    """The check digit to append to `payload` (used by tests and the synthetic evaluation set to build valid numbers)."""
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


# ---- context ---------------------------------------------------------------------------------------------------------------------
CONTEXT_WINDOW = 40                                            # characters either side of the match
AADHAAR_CONTEXT = re.compile(r"aadhaar|aadhar|adhar|\buidai?\b|\buid\b|unique\s+identification|enrol+ment\s+(?:no|number|id)|\u0906\u0927\u093e\u0930", re.I)
PAN_CONTEXT = re.compile(r"\bpan\b|permanent\s+account|income[\s-]*tax|\bitr\b", re.I)
PHONE_CONTEXT = re.compile(r"\b(?:mobile|mob|phone|ph|tel|telephone|contact|whatsapp|call|cell|landline|reach\s+me)\b", re.I)


def _near(text: str, start: int, end: int, ctx: re.Pattern) -> bool:
    return bool(ctx.search(text[max(0, start - CONTEXT_WINDOW):start] + " " + text[end:end + CONTEXT_WINDOW]))


# ---- Aadhaar ---------------------------------------------------------------------------------------------------------------------
# A 4-4-4 group must stand alone: not the first or last three groups of a longer 4-4-4-4 number (a card), which would otherwise validate by chance.
_AADHAAR_GROUPED = re.compile(r"(?<![\d-])(?<!\d[ -])[2-9]\d{3}([ -])\d{4}\1\d{4}(?![\d-])(?![ -]\d)")
_AADHAAR_BARE = re.compile(r"(?<![\d-])[2-9]\d{11}(?![\d-])")


def find_aadhaar(text: str) -> list[tuple[int, int, float, str]]:
    out = []
    for m in list(_AADHAAR_GROUPED.finditer(text)) + list(_AADHAAR_BARE.finditer(text)):
        digits = re.sub(r"\D", "", m.group())
        valid = verhoeff_ok(digits)
        ctx = _near(text, m.start(), m.end(), AADHAAR_CONTEXT)
        grouped = m.group()[4:5] in (" ", "-")
        if ctx:
            out.append((m.start(), m.end(), 0.95 if valid else 0.8, "context" + ("+checksum" if valid else "")))
        elif grouped and valid:
            out.append((m.start(), m.end(), 0.85, "grouped+checksum"))
    return out


# ---- PAN -------------------------------------------------------------------------------------------------------------------------
# Fourth letter = holder status: A association, B body of individuals, C company, F firm, G government, H HUF, J juridical person,
# L local authority, P individual, T trust.
_PAN_UPPER = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])")
_PAN_ANY_CASE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{3}[ABCFGHJLPTabcfghjlpt][A-Za-z]\d{4}[A-Za-z](?![A-Za-z0-9])")


def find_pan(text: str) -> list[tuple[int, int, float, str]]:
    out, seen = [], set()
    for m in _PAN_UPPER.finditer(text):
        out.append((m.start(), m.end(), 0.9, "format"))
        seen.add(m.start())
    for m in _PAN_ANY_CASE.finditer(text):
        if m.start() not in seen and _near(text, m.start(), m.end(), PAN_CONTEXT):
            out.append((m.start(), m.end(), 0.85, "context"))
    return out


# ---- phone -----------------------------------------------------------------------------------------------------------------------
_MOBILE = r"[6-9]\d{4}[ -]?\d{5}"
_PHONE_PREFIXED = re.compile(r"(?<![\w-])(?:\(?\+91\)?[ -]?|91[ -]|0)" + _MOBILE + r"(?![\w-])")
_PHONE_GROUPED = re.compile(r"(?<![\w-])[6-9]\d{4}[ -]\d{5}(?![\w-])")
_PHONE_BARE = re.compile(r"(?<![\w-])[6-9]\d{9}(?![\w-])")
_PHONE_LANDLINE = re.compile(r"(?<![\w-])0\d{2,4}[ -]\d{6,8}(?![\w-])")


def find_phone(text: str) -> list[tuple[int, int, float, str]]:
    out, taken = [], []

    def add(m, score, detail):
        if not any(m.start() < e and s < m.end() for s, e in taken):
            taken.append((m.start(), m.end()))
            out.append((m.start(), m.end(), score, detail))

    for m in _PHONE_PREFIXED.finditer(text):
        add(m, 0.9, "prefix")
    for m in _PHONE_GROUPED.finditer(text):
        add(m, 0.8, "grouped")
    for m in _PHONE_LANDLINE.finditer(text):
        add(m, 0.7, "landline")
    for m in _PHONE_BARE.finditer(text):
        if _near(text, m.start(), m.end(), PHONE_CONTEXT):
            add(m, 0.8, "context")
    return out
