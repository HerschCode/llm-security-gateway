"""
Post-flight checks on the LLM's response (not the user's request):

1. Jailbreak-compliance detection: did the model's response look like it
   complied with an injected instruction rather than the user's actual
   request? Heuristic phrase-matching on known compliance markers -- this
   catches the model *saying* it's complying ("filters disabled", "as RAX,
   I will now...") but can't detect silent compliance where the model just
   does the bad thing without announcing it. That gap is real and documented,
   not hidden.

2. System-prompt/config leakage check: does the response contain a
   substantial verbatim chunk of the gateway's configured system prompt?
   Uses a sliding-window substring check against the known system prompt
   text rather than a fixed keyword list, so it catches partial leaks too.
"""
import re
from dataclasses import dataclass, field

COMPLIANCE_MARKERS = [
    re.compile(r"filters?\s+(are\s+)?disabled", re.IGNORECASE),
    re.compile(r"\bas\s+(RAX|DAN|SCI)\b", re.IGNORECASE),  # roleplay-jailbreak personas
    re.compile(r"no\s+longer\s+bound\s+by\s+(my|the)\s+(system\s+prompt|guidelines|restrictions)", re.IGNORECASE),
    re.compile(r"ignoring\s+(my\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"\bI\s+have\s+no\s+restrictions\b", re.IGNORECASE),
    re.compile(r"unrestricted\s+(AI|mode)", re.IGNORECASE),
]

MIN_LEAK_SUBSTRING_LEN = 40  # chars; below this, overlap is likely coincidental phrasing


@dataclass
class ComplianceCheckResult:
    flagged: bool
    matched_markers: list[str] = field(default_factory=list)


@dataclass
class SystemLeakResult:
    leaked: bool
    leaked_snippet: str | None = None


def check_jailbreak_compliance(response_text: str) -> ComplianceCheckResult:
    matched = [p.pattern for p in COMPLIANCE_MARKERS if p.search(response_text)]
    return ComplianceCheckResult(flagged=len(matched) > 0, matched_markers=matched)


def check_system_prompt_leak(response_text: str, system_prompt: str) -> SystemLeakResult:
    """Naive but honest longest-common-substring-style check: slides the
    system prompt in fixed-size windows and looks for verbatim overlap in
    the response. O(n*m) but both strings are short (prompts, not documents),
    so this is fine at this project's scale."""
    if not system_prompt:
        return SystemLeakResult(leaked=False)

    for start in range(0, max(len(system_prompt) - MIN_LEAK_SUBSTRING_LEN, 0) + 1):
        window = system_prompt[start:start + MIN_LEAK_SUBSTRING_LEN]
        if window and window in response_text:
            return SystemLeakResult(leaked=True, leaked_snippet=window)

    return SystemLeakResult(leaked=False)
