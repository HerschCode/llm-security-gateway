"""
Text normalization pre-processing applied to all input before detection.

Normalizes surface-level obfuscations that could defeat pattern matching and
classifier tokenization without changing the semantic content of the text.
This runs BEFORE all three detection layers, so every layer benefits.

Normalizations applied (in order):
  1. Unicode normalization (NFC): resolves composed/decomposed character forms,
     e.g. 'ﬁ' (fi ligature, U+FB01) → 'fi'; 'é' (U+00E9) and 'e' + combining
     acute (U+0301 after 'e') → same NFC form.
  2. Zero-width character stripping: removes U+200B (ZWSP), U+200C (ZWNJ),
     U+200D (ZWJ), U+FEFF (BOM/ZWNBSP), U+2060 (WJ) — invisible characters
     inserted between letters to break tokenization while keeping text visually
     identical. Found as a real detection gap in scripts/paraphrase_robustness.py:
     space_insert drops classifier detection 48% → 4%.
  3. Homoglyph normalization: replaces Cyrillic/Greek lookalike characters that
     are visually identical to Latin letters (e.g. Cyrillic 'а' U+0430 → 'a',
     Greek 'ο' U+03BF → 'o'). A non-exhaustive table covering the most common
     cases; full homoglyph defense would require a confusables database.
  4. Excess whitespace collapse: normalizes multiple spaces/tabs/newlines to
     single space, since detectors treat "ig n o r e" differently from "ignore".

PII redaction (pii.py) runs after normalization — the redactor sees the
already-normalized text, which is correct: you want to detect/redact the actual
semantic content, not the original encoded form.
"""
import re
import unicodedata

# Zero-width and invisible Unicode characters that are semantically empty
# but break tokenization. Extended list covers the most common evasion chars.
_ZERO_WIDTH = re.compile(
    "["
    "​"  # ZERO WIDTH SPACE
    "‌"  # ZERO WIDTH NON-JOINER
    "‍"  # ZERO WIDTH JOINER
    "‎"  # LEFT-TO-RIGHT MARK
    "‏"  # RIGHT-TO-LEFT MARK
    "⁠"  # WORD JOINER
    "⁡"  # FUNCTION APPLICATION
    "⁢"  # INVISIBLE TIMES
    "⁣"  # INVISIBLE SEPARATOR
    "⁤"  # INVISIBLE PLUS
    "﻿"  # ZERO WIDTH NO-BREAK SPACE / BOM
    "­"  # SOFT HYPHEN
    "]"
)

# Homoglyph map: common Cyrillic and Greek lookalikes → ASCII equivalent.
# Deliberately conservative — only characters visually identical to ASCII.
_HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
    # Mathematical bold/italic variants (sometimes used for evasion)
    "𝐚": "a", "𝐛": "b", "𝐜": "c",
})


def normalize(text: str) -> str:
    """Apply all normalization steps and return the cleaned text.
    The original text is never modified; normalization is applied to a copy
    for detection purposes only. The gateway logs the normalized form alongside
    the original so analysts can see what transformation was applied."""
    # 1. Unicode normalization (compose canonical equivalents)
    text = unicodedata.normalize("NFC", text)
    # 2. Strip zero-width characters
    text = _ZERO_WIDTH.sub("", text)
    # 3. Homoglyph substitution
    text = text.translate(_HOMOGLYPHS)
    # 4. Collapse excess whitespace (but preserve single newlines for structure)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
