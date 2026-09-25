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

What this is NOT (see docs/action-firewall.md): it is not CaMeL-style data-flow control. CaMeL
(Debenedetti et al. 2025) has a privileged LLM that only sees trusted input plan the actions, a
quarantined LLM that reads untrusted data but cannot call tools, and a capability interpreter that
tracks data flow exactly. This module is a string-overlap heuristic on the observable strings. It is
evaded by anything that rewrites the text: paraphrase, translation, encoding, summarisation. Those
cases are measured, not hidden, in reports/p3_action_firewall.json; the approval gate is the backstop.
"""
import re
from dataclasses import dataclass, field

_TOKEN = re.compile(r"[a-z0-9]+")
# Bounds per session: the endpoints that feed this are unauthenticated on the public demo and the host has 512 MB.
MAX_SPAN_CHARS = 20_000
MAX_SPANS = 50
MAX_TOTAL_CHARS = 100_000


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def _shingles(tokens: list[str], n: int) -> set[tuple]:
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


@dataclass
class Span:
    kind: str
    trust: str
    tokens: list[str]
    text: str
    shingles: set = field(default_factory=set)


@dataclass
class TaintFinding:
    field: str
    tainted: bool
    score: float                 # share of the value's word n-grams found only in untrusted spans
    source_kind: str | None = None
    snippet: str | None = None


class TaintTracker:
    def __init__(self, shingle_n: int = 3, threshold: float = 0.5, short_words: int = 2):
        self.n = shingle_n
        self.threshold = threshold
        self.short_words = short_words
        self.spans: list[Span] = []

    def add(self, kind: str, text: str, trust: str):
        if trust not in ("trusted", "untrusted"):
            raise ValueError("trust must be 'trusted' or 'untrusted'")
        text = (text or "")[:MAX_SPAN_CHARS]
        toks = _tokens(text)
        if not toks:
            return
        self.spans.append(Span(kind, trust, toks, text, _shingles(toks, self.n)))
        while len(self.spans) > MAX_SPANS or (len(self.spans) > 1 and sum(len(s.text) for s in self.spans) > MAX_TOTAL_CHARS):
            self.spans.pop(0)      # oldest first

    # ---- analysis ----------------------------------------------------------------------------

    @staticmethod
    def _contains(haystack: list[str], needle: list[str]) -> bool:
        m = len(needle)
        return m > 0 and any(haystack[i:i + m] == needle for i in range(len(haystack) - m + 1))

    def _value_finding(self, name: str, value: str) -> TaintFinding:
        toks = _tokens(value)
        if not toks:
            return TaintFinding(name, False, 0.0)
        trusted = [s for s in self.spans if s.trust == "trusted"]
        untrusted = [s for s in self.spans if s.trust == "untrusted"]
        if not untrusted:
            return TaintFinding(name, False, 0.0)

        if len(toks) <= self.short_words:
            # short values (IDs, entity names): exact word-sequence match
            if any(self._contains(s.tokens, toks) for s in trusted):
                return TaintFinding(name, False, 0.0)
            for s in untrusted:
                if self._contains(s.tokens, toks):
                    return TaintFinding(name, True, 1.0, s.kind, self._snippet(s, toks))
            return TaintFinding(name, False, 0.0)

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
        return TaintFinding(name, False, round(best_score, 3))

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
