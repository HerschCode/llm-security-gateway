"""
Post-flight role-based data exposure check.

Reuses Project 2's role concept (clearance levels on structured data) rather
than reinventing an access model: each role has a set of field/data "tags" it's
cleared to see, and a response is flagged if it contains content tagged above
the requester's clearance. This is a heuristic keyword/tag scan, not a real
data-lineage tracker -- it can't see *why* the LLM's response contains a given
field, only that restricted-looking content is present. That's an honest
limitation: a determined model could still leak restricted data phrased in a
way this scan doesn't recognize. Documented here rather than overclaimed.
"""
import re
from dataclasses import dataclass, field

# Mirrors Project 2's role hierarchy (ops-assistant domain): each role is
# cleared for its own tier plus everything below it.
ROLE_HIERARCHY = ["employee", "manager", "admin"]

# Tag -> minimum role required to see content matching that tag's pattern.
# Patterns are illustrative of an ops/SLA domain (matching Projects 1 and 2),
# not exhaustive -- a real deployment would generate this from the actual
# data schema's field-level classifications, not a fixed regex list.
RESTRICTED_TAGS = {
    "salary_data": (re.compile(r"\bsalary\b|\bcompensation\b|\$\d{2,3},\d{3}\b", re.IGNORECASE), "admin"),
    "employee_pii": (re.compile(r"\bssn\b|\bsocial security\b|\bhome address\b", re.IGNORECASE), "manager"),
    "full_incident_log": (re.compile(r"\bfull incident log\b|\bunredacted\b", re.IGNORECASE), "manager"),
    "org_wide_records": (re.compile(r"\ball employees\b|\bevery user in the org\b|\bfull org\w* database\b", re.IGNORECASE), "admin"),
}


@dataclass
class RoleExposureResult:
    exposed: bool
    matched_tags: list[str] = field(default_factory=list)
    redacted_text: str | None = None


def _role_rank(role: str) -> int:
    try:
        return ROLE_HIERARCHY.index(role)
    except ValueError:
        return 0  # unknown role treated as lowest clearance, fail closed


def check(response_text: str, requester_role: str) -> RoleExposureResult:
    requester_rank = _role_rank(requester_role)
    matched_tags = []
    redacted = response_text

    for tag, (pattern, min_role) in RESTRICTED_TAGS.items():
        min_rank = _role_rank(min_role)
        if requester_rank < min_rank and pattern.search(redacted):
            matched_tags.append(tag)
            redacted = pattern.sub(f"[REDACTED_{tag.upper()}_INSUFFICIENT_CLEARANCE]", redacted)

    return RoleExposureResult(
        exposed=len(matched_tags) > 0,
        matched_tags=matched_tags,
        redacted_text=redacted if matched_tags else None,
    )
