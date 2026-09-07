"""
BEST-EFFORT RECONSTRUCTION -- see project2_agent/documents.py's module
docstring. A guess at "a refusal-policy decision table," one of Project 2's
stated components. Real wording, categories, and structure are unknown --
this invents a plausible small table in the same spirit.
"""

REFUSAL_TABLE = {
    "insufficient_clearance": (
        "I can't share that -- it's outside what your current role is cleared to see. "
        "If you need access, ask your manager to request an elevation."
    ),
    "ambiguous_scope": (
        "I want to make sure I get this right -- could you clarify exactly what "
        "you're looking for? That request could mean a few different things."
    ),
    "out_of_domain": (
        "That's outside what I'm able to help with -- I'm scoped to ops/SLA/incident "
        "topics for this team."
    ),
    "unknown_tool": (
        "I don't have a way to do that right now."
    ),
}

DEFAULT_REFUSAL = "I'm not able to help with that request."


def get_refusal_message(reason_code: str) -> str:
    for key, message in REFUSAL_TABLE.items():
        if reason_code.startswith(key):
            return message
    return DEFAULT_REFUSAL
