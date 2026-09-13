"""
Text normalization pre-processing applied to all input before detection.

Normalizes surface-level obfuscations that could defeat pattern matching and
classifier tokenization without changing the semantic content of the text.
This runs BEFORE all three detection layers, so every layer benefits.

Normalizations applied (in order):
  1. Unicode normalization (NFC): resolves composed/decomposed character forms.
  2. Zero-width character stripping: removes U+200B (ZWSP), U+200C (ZWNJ),
     U+200D (ZWJ), U+FEFF (BOM), U+2060 (WJ), and related invisible characters.
     Found as a real detection gap (space_insert: classifier 48% → 4%; fixed
     by this step back to 48%).
  3. Homoglyph normalization: Cyrillic/Greek lookalikes → ASCII equivalent.
     Covers GW-012 (Cyrillic homoglyph injection in eval corpus).
  4. Encoding decoding:
     a. Base64 segments: detects token-shaped base64 blobs and appends the
        decoded plaintext for detection. Covers GW-010 (base64 wrapper attacks).
     b. Hex strings: %xx URL encoding and 0x-prefixed hex → decoded chars.
     c. Leet-speak: common digit substitutions (0→o, 3→e, 1→l, 4→a, 5→s,
        7→t) in isolation so "1gn0r3" → "ignore". Covers GW-011.
  5. Excess whitespace collapse.

Design note: encoding decoding APPENDS the decoded form rather than replacing
the original text. This is intentional — the original text stays for human
readability in logs, and the decoded form is what the detectors see. Appending
both means no false negatives from partial decoding failures.
"""
import base64
import re
import unicodedata

# ---------------------------------------------------------------------------
# Step 2: Zero-width characters
# ---------------------------------------------------------------------------
_ZERO_WIDTH = re.compile(
    "["
    "​"   # ZERO WIDTH SPACE
    "‌"   # ZERO WIDTH NON-JOINER
    "‍"   # ZERO WIDTH JOINER
    "‎"   # LEFT-TO-RIGHT MARK
    "‏"   # RIGHT-TO-LEFT MARK
    "⁠"   # WORD JOINER
    "⁡"   # FUNCTION APPLICATION
    "⁢"   # INVISIBLE TIMES
    "⁣"   # INVISIBLE SEPARATOR
    "⁤"   # INVISIBLE PLUS
    "﻿"   # ZERO WIDTH NO-BREAK SPACE / BOM
    "­"   # SOFT HYPHEN
    "]"
)

# ---------------------------------------------------------------------------
# Step 3: Homoglyphs
# ---------------------------------------------------------------------------
_HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X",
    # Mathematical bold/italic variants
    "\U0001d41a": "a", "\U0001d41b": "b", "\U0001d41c": "c",
})

# ---------------------------------------------------------------------------
# Step 4a: Base64 detection
# ---------------------------------------------------------------------------
# Matches base64 segments of at least 20 chars (enough to encode "ignore all
# previous instructions"). Requires proper padding or a length divisible by 4.
_B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decode_base64_segments(text: str) -> str:
    """Find base64-looking blobs, decode them, and append the decoded plaintext.
    Conservative: only decodes if the result is printable ASCII (avoids false
    positives on tokens that happen to be valid base64 by chance)."""
    extras = []
    for match in _B64_PATTERN.finditer(text):
        blob = match.group(0)
        # Pad to multiple of 4
        pad = (-len(blob)) % 4
        try:
            decoded = base64.b64decode(blob + "=" * pad, validate=True)
            decoded_str = decoded.decode("utf-8", errors="strict")
            # Only keep if it looks like natural language (printable, has spaces)
            if decoded_str.isprintable() and " " in decoded_str:
                extras.append(decoded_str.strip())
        except Exception:
            pass
    if extras:
        return text + " " + " ".join(extras)
    return text


# ---------------------------------------------------------------------------
# Step 4b: URL percent-encoding and 0x hex
# ---------------------------------------------------------------------------
_PCT_ENCODED = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_HEX_WORD = re.compile(r"\b0x([0-9A-Fa-f]{2,})\b")


def _decode_hex_segments(text: str) -> str:
    def replace_pct(m: re.Match) -> str:
        try:
            return bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)

    def replace_0x(m: re.Match) -> str:
        try:
            raw = bytes.fromhex(m.group(1))
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)

    t = _PCT_ENCODED.sub(replace_pct, text)
    t = _HEX_WORD.sub(replace_0x, t)
    return t


# ---------------------------------------------------------------------------
# Step 4c: Leet-speak
# ---------------------------------------------------------------------------
# Applied per-word: only substitute if the word has ≥2 digit replacements
# (reduces false positives on legitimate numerals like "Q3" or "P1").
_LEET = str.maketrans("01345789", "oieasltg")


def _normalize_leet(text: str) -> str:
    words = text.split()
    result = []
    for word in words:
        digit_count = sum(1 for ch in word if ch in "013457")
        if digit_count >= 2:
            result.append(word.translate(_LEET))
        else:
            result.append(word)
    return " ".join(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize(text: str) -> str:
    """Apply all normalization steps and return the cleaned text.

    Detection always runs against the normalized form; the original text is
    logged alongside it so analysts can reconstruct what obfuscation was used."""
    # 1. Unicode NFC
    text = unicodedata.normalize("NFC", text)
    # 2. Strip zero-width characters
    text = _ZERO_WIDTH.sub("", text)
    # 3. Homoglyph substitution
    text = text.translate(_HOMOGLYPHS)
    # 4a. Base64 decoding (appends decoded content)
    text = _decode_base64_segments(text)
    # 4b. URL / hex decoding
    text = _decode_hex_segments(text)
    # 4c. Leet-speak
    text = _normalize_leet(text)
    # 5. Whitespace collapse
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
