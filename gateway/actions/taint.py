"""
Provenance (taint) tracking for tool-call arguments.

Threat: an agent reads untrusted text (a retrieved policy document, a user upload) that contains
an instruction, and then copies attacker-chosen content into the arguments of a write tool. The
question this module answers is narrow and mechanical: "did this argument value come from untrusted
text, without any corroboration from a trusted source?"

Method: every text that enters the agent's context is registered as a span with a trust label
(trusted: the user's own messages and outputs of trusted tools; untrusted: retrieved documents, uploads,
outputs of tools the policy marks untrusted). An argument is TAINTED when most of its word 3-grams (or,
for values of one or two words, its exact word sequence) occur in untrusted spans and NOT in trusted
ones. Trusted wins: a value the user typed themselves, or that a trusted analytics tool returned, is not
tainted even if a poisoned document also repeats it (that lets an attacker pick a target that is also
legitimate, which is harmless by construction).

Canonicalisation (added after the red-team pass, reports/redteam-2026-09.md RT-10 and RT-11). Both sides
are compared after: Unicode NFKC and accent folding, removal of invisible characters, case folding,
number words folded to digits ("nine thousand" -> 9000), and base64/hex runs decoded into an extra
span (or an extra reading of the value). On top of the word matching, short values (up to
`compact_max_tokens` words, i.e. identifiers and entity names) are also matched on their COMPACT form:
the letters and digits with every separator removed, aligned to token boundaries. That makes `ZX9000`,
`Z-X-9000` and `ZX 9 000` the same identifier as `ZX-9000`, and lets a value that adds an extra word to
a copied identifier still match on the copied part. A compact match needs an identifier-like window (a
digit with 5+ characters, pure digits with 6+, or a multi-word window of 8+ letters) covering at least a
third of the value, and never fires when the same characters occur in a trusted span.

What this is NOT (see docs/action-firewall.md): it is not CaMeL-style data-flow control. CaMeL
(Debenedetti et al. 2025) has a privileged LLM that only sees trusted input plan the actions, a
quarantined LLM that reads untrusted data but cannot call tools, and a capability interpreter that
tracks data flow exactly. This module is a string-overlap heuristic on the observable strings. It is
still evaded by anything that changes the wording rather than the spelling: paraphrase, translation,
an identifier split across sentences, an acronym. Those cases are measured, not hidden, in
reports/p3_taint_upgrade.json; the approval gate is the backstop.
"""
import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

_TOKEN = re.compile(r"[a-z0-9]+")
# Bounds per session: the endpoints that feed this are unauthenticated on the public demo and the host has 512 MB.
MAX_SPAN_CHARS = 20_000
MAX_SPANS = 50
MAX_TOTAL_CHARS = 100_000

# Invisible characters that carry no meaning in an identifier: soft hyphen, combining grapheme joiner, Arabic letter mark, Hangul fillers,
# Mongolian variation selectors, zero-width and directional marks, invisible operators, BOM, and the Unicode Tag block.
_INVISIBLE_RANGES = [(0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180E), (0x200B, 0x200F),
                     (0x202A, 0x202E), (0x2060, 0x2064), (0x206A, 0x206F), (0xFEFF, 0xFEFF), (0xE0000, 0xE007F)]
_INVISIBLE = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _INVISIBLE_RANGES) + "]")


def _canon(text: str) -> str:
    """NFKC (fullwidth forms, ligatures, ...), invisible characters removed, accents folded, case folded."""
    t = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    t = "".join(c for c in unicodedata.normalize("NFKD", t) if not unicodedata.combining(c))
    return t.casefold()


# ---- number words -> digits ("ZX nine thousand" is the same identifier as ZX-9000) ----------------------------------
_UNITS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen".split())}
_TENS = {w: 10 * (i + 2) for i, w in enumerate("twenty thirty forty fifty sixty seventy eighty ninety".split())}
_SCALES = {"thousand": 10**3, "million": 10**6, "billion": 10**9}
_DIGIT_WORDS = {w: i for i, w in enumerate("zero one two three four five six seven eight nine".split())} | {"oh": 0}
_NUMBER_WORDS = set(_UNITS) | set(_TENS) | set(_SCALES) | {"hundred", "oh"}


def _parse_number_run(run: list[str]) -> str | None:
    """A run of number words as digits, or None if it does not form a number. "nine zero zero zero" -> 9000 (digit by digit),
    "nine thousand" -> 9000, "one hundred and five" -> 105."""
    if len(run) >= 2 and all(w in _DIGIT_WORDS for w in run):
        return "".join(str(_DIGIT_WORDS[w]) for w in run)
    total = current = 0
    last = None
    for w in run:
        if w in _UNITS:
            if last == "unit" or (last == "tens" and _UNITS[w] >= 10):
                return None
            current += _UNITS[w]
            last = "unit"
        elif w in _TENS:
            if last in ("unit", "tens"):
                return None
            current += _TENS[w]
            last = "tens"
        elif w == "hundred":
            current = (current or 1) * 100
            last = "hundred"
        elif w in _SCALES:
            total += (current or 1) * _SCALES[w]
            current = 0
            last = "scale"
        else:
            return None
    return str(total + current)


def _fold_numbers(tokens: list[str]) -> list[str]:
    out, i, n = [], 0, len(tokens)
    while i < n:
        j = i
        while j < n and (tokens[j] in _NUMBER_WORDS or (tokens[j] == "and" and j > i and j + 1 < n and tokens[j + 1] in _NUMBER_WORDS)):
            j += 1
        for k in range(j, i, -1):                                  # the longest prefix of the run that is a number
            if tokens[k - 1] == "and":
                continue
            value = _parse_number_run([t for t in tokens[i:k] if t != "and"])
            if value is not None:
                out.append(value)
                i = k
                break
        else:
            out.append(tokens[i])
            i += 1
    return out


def _tokens(text: str) -> list[str]:
    return _fold_numbers(_TOKEN.findall(_canon(text)))


# ---- base64 / hex runs -> decoded text -----------------------------------------------------------------------------
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){6,}(?![0-9A-Fa-f])")
_SANE = re.compile(r"[A-Za-z0-9 _.,:;@/\-]")


def _sane_text(decoded: str) -> bool:
    """Decoded bytes count only if they read like text or an identifier: mostly letters, digits, spaces and light punctuation."""
    return len(decoded) >= 4 and decoded.isprintable() and len(_SANE.findall(decoded)) >= 0.9 * len(decoded)


def _decode_runs(text: str) -> str:
    """`text` with every base64 or hex run that decodes to sane text replaced by the decoded text (unchanged if none do)."""
    def b64(m: re.Match) -> str:
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob.rstrip("=") + "=" * (-len(blob.rstrip("=")) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError):
            return blob
        return decoded if _sane_text(decoded) else blob

    def hexrun(m: re.Match) -> str:
        try:
            decoded = bytes.fromhex(m.group(0)).decode("utf-8")
        except ValueError:
            return m.group(0)
        return decoded if _sane_text(decoded) else m.group(0)

    return _HEX_RUN.sub(hexrun, _B64_RUN.sub(b64, text))


def _shingles(tokens: list[str], n: int) -> set[tuple]:
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


@dataclass
class Span:
    kind: str
    trust: str
    tokens: list[str]
    text: str
    shingles: set = field(default_factory=set)
    compact: str = ""                                     # the tokens joined with no separator
    starts: dict = field(default_factory=dict)            # character offset in `compact` -> index of the token that starts there
    ends: dict = field(default_factory=dict)              # character offset in `compact` -> index just past the token that ends there


@dataclass
class TaintFinding:
    field: str
    tainted: bool
    score: float                 # share of the value's word n-grams found only in untrusted spans (compact matches: share of the value's characters)
    source_kind: str | None = None
    snippet: str | None = None


class TaintTracker:
    def __init__(self, shingle_n: int = 3, threshold: float = 0.5, short_words: int = 2,
                 compact_max_tokens: int = 6, min_coverage: float = 0.34):
        self.n = shingle_n
        self.threshold = threshold
        self.short_words = short_words
        self.compact_max_tokens = compact_max_tokens
        self.min_coverage = min_coverage
        self.spans: list[Span] = []

    @staticmethod
    def _make_span(kind: str, trust: str, text: str, tokens: list[str], n: int) -> Span:
        span = Span(kind, trust, tokens, text, _shingles(tokens, n))
        pos = 0
        for i, tok in enumerate(tokens):
            span.starts[pos] = i
            pos += len(tok)
            span.ends[pos] = i + 1
        span.compact = "".join(tokens)
        return span

    def add(self, kind: str, text: str, trust: str):
        if trust not in ("trusted", "untrusted"):
            raise ValueError("trust must be 'trusted' or 'untrusted'")
        text = (text or "")[:MAX_SPAN_CHARS]
        toks = _tokens(text)
        if not toks:
            return
        self.spans.append(self._make_span(kind, trust, text, toks, self.n))
        decoded = _decode_runs(text)                       # a base64/hex payload in the text is read too, as a span of its own
        if decoded != text:
            dtoks = _tokens(decoded)
            if dtoks:
                self.spans.append(self._make_span(f"{kind}(decoded)", trust, decoded, dtoks, self.n))
        while len(self.spans) > MAX_SPANS or (len(self.spans) > 1 and sum(len(s.text) for s in self.spans) > MAX_TOTAL_CHARS):
            self.spans.pop(0)      # oldest first

    # ---- analysis ----------------------------------------------------------------------------

    @staticmethod
    def _contains(haystack: list[str], needle: list[str]) -> bool:
        m = len(needle)
        return m > 0 and any(haystack[i:i + m] == needle for i in range(len(haystack) - m + 1))

    @staticmethod
    def _aligned_tokens(span: Span, window: str) -> int:
        """How many of the span's tokens an occurrence of `window` in the span's compact text covers, counting only occurrences that
        start and end on token boundaries; 0 if there is none."""
        idx = span.compact.find(window)
        while idx != -1:
            end = idx + len(window)
            if idx in span.starts and end in span.ends:
                return span.ends[end] - span.starts[idx]
            idx = span.compact.find(window, idx + 1)
        return 0

    @staticmethod
    def _identifier_like(window: str) -> bool:
        has_digit, has_alpha = any(c.isdigit() for c in window), any(c.isalpha() for c in window)
        if has_digit:
            return len(window) >= (5 if has_alpha else 6)          # zx9000, case1042, or 6+ digits
        return len(window) >= 8                                    # a name such as blueharbor (single-token letters must also be a join: see below)

    def _compact_finding(self, name: str, toks: list[str], trusted: list[Span], untrusted: list[Span]) -> TaintFinding | None:
        """Boundary-insensitive match of the value's letters and digits against untrusted spans, longest window first."""
        n = len(toks)
        if not 1 <= n <= self.compact_max_tokens:
            return None
        total = sum(len(t) for t in toks)
        for size in range(n, 0, -1):
            for i in range(n - size + 1):
                window = "".join(toks[i:i + size])
                if len(window) / total < self.min_coverage or not self._identifier_like(window):
                    continue
                if any(self._aligned_tokens(s, window) for s in trusted):
                    continue                                        # trusted wins
                for s in untrusted:
                    spanned = self._aligned_tokens(s, window)
                    # a single letters-only token counts only if it is a JOIN of several tokens in the document ("blueharborltd" for
                    # "Blue Harbor Ltd"); a plain word that the document also contains is not evidence of copying
                    if spanned and (size >= 2 or any(c.isdigit() for c in window) or spanned >= 2):
                        return TaintFinding(name, True, round(len(window) / total, 3), s.kind, self._snippet(s, toks[i:i + size]))
        return None

    def _finding_for_tokens(self, name: str, toks: list[str], trusted: list[Span], untrusted: list[Span]) -> TaintFinding:
        if len(toks) <= self.short_words:
            # short values (IDs, entity names): exact word-sequence match
            if any(self._contains(s.tokens, toks) for s in trusted):
                return TaintFinding(name, False, 0.0)
            for s in untrusted:
                if self._contains(s.tokens, toks):
                    return TaintFinding(name, True, 1.0, s.kind, self._snippet(s, toks))
            return self._compact_finding(name, toks, trusted, untrusted) or TaintFinding(name, False, 0.0)

        n = min(self.n, len(toks))
        mine = _shingles(toks, n)
        trusted_sh = set().union(*(_shingles(s.tokens, n) for s in trusted)) if trusted else set()
        best_score, best_span = 0.0, None
        for s in untrusted:
            only_untrusted = (mine & _shingles(s.tokens, n)) - trusted_sh
            score = len(only_untrusted) / len(mine)
            if score > best_score:
                best_score, best_span = score, s
        if best_span is not None and best_score >= self.threshold:
            return TaintFinding(name, True, round(best_score, 3), best_span.kind, self._snippet(best_span, toks[:n]))
        return self._compact_finding(name, toks, trusted, untrusted) or TaintFinding(name, False, round(best_score, 3))

    def _value_finding(self, name: str, value: str) -> TaintFinding:
        untrusted = [s for s in self.spans if s.trust == "untrusted"]
        if not untrusted:
            return TaintFinding(name, False, 0.0)
        trusted = [s for s in self.spans if s.trust == "trusted"]
        readings = [value]
        decoded = _decode_runs(value)                                # the value may itself carry an encoded payload
        if decoded != value:
            readings.append(decoded)
        worst = TaintFinding(name, False, 0.0)
        for reading in readings:
            toks = _tokens(reading)
            if not toks:
                continue
            finding = self._finding_for_tokens(name, toks, trusted, untrusted)
            if finding.tainted:
                return finding
            if finding.score > worst.score:
                worst = finding
        return worst

    @staticmethod
    def _snippet(span: Span, needle: list[str]) -> str:
        idx = span.text.lower().find(needle[0])
        start = max(0, idx - 30) if idx >= 0 else 0
        return span.text[start:start + 120].replace("\n", " ")

    def analyze(self, args: dict, fields: list[str] | None = None) -> list[TaintFinding]:
        """Findings for string values in `args` (nested keys use dotted paths). If `fields` is given,
        only those top-level argument names are examined."""
        out = []

        def walk(prefix: str, value):
            if isinstance(value, str):
                out.append(self._value_finding(prefix, value))
            elif isinstance(value, dict):
                for k, v in value.items():
                    walk(f"{prefix}.{k}", v)
            elif isinstance(value, (list, tuple)):
                for i, v in enumerate(value):
                    walk(f"{prefix}[{i}]", v)

        for name, value in args.items():
            if fields is None or name in fields:
                walk(name, value)
        return out
