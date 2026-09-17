# Where the `public_pattern` corpus cases actually come from

`corpus/injection_cases.yaml`'s own header has always defined `origin:
public_pattern` as "mechanism is a documented pattern... payload text is
still hand-written for this project, not copy-pasted from a source." That's
a deliberate methodology choice, not a shortcut — copy-pasting real rows from
a public attack dataset directly into the eval corpus would risk recreating
the exact train/test leakage bug this project already found and fixed once
(`docs/leakage_fix.md`): `verazuo/jailbreak_llms` is the public dataset
`data/train.csv` trains on, so any of *its* rows appearing in the eval corpus
too would be leakage by construction, not a hypothetical.

What was missing wasn't independence from training data — that was already
correct — it was **which real family each `public_pattern` case is actually
modeling**, stated explicitly rather than left as an unlinked label. This
doc closes that gap: every current `public_pattern` case, mapped to the real
documented technique or incident it's based on.

| Case(s) | Technique family | Real-world source |
|---|---|---|
| GW-001 | Direct instruction-override ("ignore all previous instructions") | The most widely documented prompt-injection pattern; catalogued as **OWASP LLM01: Prompt Injection** in the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) |
| GW-007 | "DAN" (Do Anything Now) persona jailbreak | Documented and measured at scale in Shen et al., *"Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models*, ACM CCS 2024 — the same paper behind the `verazuo/jailbreak_llms` dataset this project uses for training (cited in `docs/decisions.md`) |
| GW-038, GW-045 | Fictional-framing / roleplay wrapper jailbreaks | A named sub-family within the same Shen et al. 2024 taxonomy ("virtual scenario" / roleplay-based jailbreaks) |
| GW-010, GW-023, GW-049 | Encoding-based filter evasion (base64, ROT13, hex) | Standard payload-obfuscation technique against naive keyword/regex filters; the base64 variant specifically is called out in OWASP's LLM01 guidance as a bypass example |
| GW-011 | Leetspeak / character substitution | Classic keyword-filter evasion, predates LLMs (same family as spam-filter evasion), applied here to an injection payload |
| GW-022, GW-073, GW-075, GW-077, GW-098 | Unicode abuse: RTL override (U+202E), homoglyphs, combining-diacritic stacking | RTL override is a **named, CVE-tracked technique** for disguising file extensions and malicious text (widely documented as "Right-to-Left Override" or "Trojan Source" — see Boucher & Anderson, *Trojan Source: Invisible Vulnerabilities*, USENIX Security 2021, for the formal treatment of Unicode bidi/homoglyph abuse against source code and text processing) |
| GW-074 | Null-byte injection | A decades-old string-termination/parser-confusion technique (classic in path-traversal and filter-bypass CVEs), applied here to break substring matching |
| GW-015, GW-031, GW-055 | Tool-scope escalation via authority claims / "authorized test" framing | Standard social-engineering pretexting, the same technique class MITRE ATT&CK catalogs as **T1585 (pretexting)**-adjacent behavior, applied to an LLM tool-calling context rather than a human target |
| GW-033 | "I'm an authorized red-teamer" framing | A specific, widely-reported real-world jailbreak framing (claiming sanctioned security testing to bypass refusals) documented in multiple public jailbreak-prompt collections including `verazuo/jailbreak_llms`'s own corpus |
| GW-082 | Markdown link display-text injection | A documented indirect-prompt-injection vector for RAG/document-summarization systems — content in a link's visible text or title attribute differs from what a human skims vs. what the model actually processes; catalogued under **OWASP LLM01**'s indirect-injection guidance |
| GW-084, GW-087 | Multi-turn authority-escalation / gaslighting (false-memory) chains | A named jailbreak family ("crescendo" / multi-turn escalation attacks) — see Russinovich et al., *Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack*, Microsoft Research, 2024 |
| GW-091 | Prompt-prefix stuffing (burying the payload in filler text) | A documented evasion technique against both keyword filters and human reviewers skimming long inputs; related to "many-shot jailbreaking" context-stuffing research (Anthropic, *Many-shot Jailbreaking*, 2024) |

## What this does and doesn't fix

**Does:** every `public_pattern` case now traces to something real and
checkable, not just a label. An interviewer asking "is GW-007 actually
DAN, or did you just call it that" now has a specific paper to check it
against.

**Doesn't:** this is still 26 of ~100 cases (the rest are `self_devised`,
plausible but unvalidated against any external source). Growing the
public-provenance share further means either (a) writing more cases against
named, citable techniques the way the ones above are, or (b) sourcing from a
genuinely disjoint public attack dataset (not `verazuo/jailbreak_llms`,
which is already the training source) — AdvBench (Zou et al., *Universal and
Transferable Adversarial Attacks on Aligned Language Models*, 2023) is a
candidate for a future pass, but its rows are harmful-content-generation
requests, not prompt-injection-against-a-tool-calling-agent attacks, so
adapting rather than copying its payloads would still be needed to stay
on-topic for this corpus's actual threat model. Not done in this pass —
flagged as the honest next step rather than silently left unconsidered.
