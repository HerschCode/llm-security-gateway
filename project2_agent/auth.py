"""
BEST-EFFORT RECONSTRUCTION -- see project2_agent/documents.py's module
docstring for the caveat. This is a guess at "tool-authorization middleware,"
one of Project 2's stated components, not the real implementation.

Each tool declares a minimum role. check_authorization() is called before a
tool executes -- this is INTERNAL to the agent, distinct from and independent
of the gateway's own role_exposure.py post-flight check, which scans the
agent's OUTPUT after the fact. Having both is intentional: it lets us test
whether the external gateway still adds value when the backend already does
some of its own enforcement, which is a more realistic and more interesting
test than the purely undefended stub_ops_agent.
"""
from dataclasses import dataclass

ROLE_HIERARCHY = ["employee", "manager", "admin"]

TOOL_CLEARANCE = {
    "lookup_ticket": "employee",
    "search_incident_logs": "employee",       # full unredacted requires manager, checked inside the tool
    "query_sla_risk": "employee",
    "lookup_employee_directory": "employee",   # own info only; others' requires manager
    "retrieve_documents": "employee",
    "query_audit_log": "manager",
    "schedule_escalation": "employee",         # own tickets only; others' requires manager
}


def _role_rank(role: str) -> int:
    try:
        return ROLE_HIERARCHY.index(role)
    except ValueError:
        return 0  # unknown role -> lowest clearance, fail closed


@dataclass
class AuthResult:
    authorized: bool
    reason: str | None = None


def check_authorization(tool_name: str, role: str) -> AuthResult:
    required_role = TOOL_CLEARANCE.get(tool_name)
    if required_role is None:
        return AuthResult(authorized=False, reason=f"unknown_tool:{tool_name}")

    if _role_rank(role) < _role_rank(required_role):
        return AuthResult(
            authorized=False,
            reason=f"insufficient_clearance: {tool_name} requires {required_role}, requester has {role}",
        )
    return AuthResult(authorized=True)
