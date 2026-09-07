"""
BEST-EFFORT RECONSTRUCTION -- see project2_agent/documents.py's module
docstring. A guess at Project 2's "7 structured tools," operating on a small
synthetic in-memory dataset in the same ops/SLA domain as Projects 1 and 3.
Real tool names, schemas, and data are unknown.

Each tool takes (role, **kwargs) and returns a plain dict result. Callers
(agent.py) are responsible for calling auth.check_authorization() first --
tools here trust that they're only invoked after that check passes, matching
a typical real agent-framework pattern (the framework enforces authorization
before the tool function body runs).
"""
from project2_agent.documents import retrieve

# Synthetic data, invented for this reconstruction.
TICKETS = {
    "INC-4471": {"status": "open", "assignee": "j.ortiz", "priority": "P1", "team": "platform"},
    "INC-4488": {"status": "closed", "assignee": "r.kim", "priority": "P2", "team": "platform"},
    "INC-4502": {"status": "open", "assignee": "t.nwosu", "priority": "P3", "team": "data"},
}

INCIDENT_LOGS = {
    "INC-4471": {
        "summary_redacted": "Firewall misconfiguration exposed a staging resource. Remediated.",
        "summary_full": "Firewall misconfiguration exposed the staging DB (contains synthetic customer records). Root cause: manual config change bypassed review. Fixed via automated validation.",
    },
    "INC-4488": {
        "summary_redacted": "Deployment rollback due to elevated error rate.",
        "summary_full": "Canary rollout at 5% traffic showed a 3.2% error rate spike; auto-rollback triggered. Root cause: unhandled null in new pricing service.",
    },
}

SLA_RISK = {
    "platform": {"breach_risk_pct": 12, "open_p1_count": 1},
    "data": {"breach_risk_pct": 4, "open_p1_count": 0},
}

EMPLOYEE_DIRECTORY = {
    "j.ortiz": {"role": "employee", "team": "platform", "manager": "r.kim", "email": "j.ortiz@example.com"},
    "r.kim": {"role": "manager", "team": "platform", "manager": "t.chen", "email": "r.kim@example.com"},
    "t.nwosu": {"role": "employee", "team": "data", "manager": "s.patel", "email": "t.nwosu@example.com"},
}

AUDIT_LOG = [
    {"actor": "r.kim", "action": "escalated INC-4471", "timestamp": "2026-08-30T10:00:00Z"},
    {"actor": "admin", "action": "reset password for j.ortiz", "timestamp": "2026-08-29T14:22:00Z"},
]


def lookup_ticket(role: str, ticket_id: str) -> dict:
    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        return {"error": f"No ticket found with id {ticket_id}"}
    return {"ticket_id": ticket_id, **ticket}


def search_incident_logs(role: str, ticket_id: str) -> dict:
    log = INCIDENT_LOGS.get(ticket_id)
    if log is None:
        return {"error": f"No incident log found for {ticket_id}"}
    # Role-scoped detail: full unredacted summary requires manager+, matching
    # the same role concept the gateway's role_exposure.py check also uses --
    # this is the agent doing ITS OWN scoping, independent of the gateway.
    if role in ("manager", "admin"):
        return {"ticket_id": ticket_id, "summary": log["summary_full"]}
    return {"ticket_id": ticket_id, "summary": log["summary_redacted"]}


def query_sla_risk(role: str, team: str) -> dict:
    risk = SLA_RISK.get(team)
    if risk is None:
        return {"error": f"No SLA risk data for team {team}"}
    return {"team": team, **risk}


def lookup_employee_directory(role: str, employee_id: str, requester_id: str | None = None) -> dict:
    entry = EMPLOYEE_DIRECTORY.get(employee_id)
    if entry is None:
        return {"error": f"No employee found: {employee_id}"}
    # Looking up someone else's info requires manager+; looking up your own is fine.
    if requester_id != employee_id and role not in ("manager", "admin"):
        return {"error": "insufficient_clearance: viewing another employee's record requires manager role"}
    return {"employee_id": employee_id, **entry}


def retrieve_documents(role: str, query: str) -> dict:
    results = retrieve(query)
    return {
        "query": query,
        "results": [
            {"doc_id": r.doc_id, "title": r.title, "snippet": r.snippet}
            for r in results
        ],
    }


def query_audit_log(role: str, actor_filter: str | None = None) -> dict:
    entries = AUDIT_LOG
    if actor_filter:
        entries = [e for e in entries if e["actor"] == actor_filter]
    return {"entries": entries}


def schedule_escalation(role: str, ticket_id: str, escalate_to: str, requester_id: str | None = None) -> dict:
    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        return {"error": f"No ticket found with id {ticket_id}"}
    # Escalating someone else's ticket requires manager+.
    if requester_id and ticket.get("assignee") != requester_id and role not in ("manager", "admin"):
        return {"error": "insufficient_clearance: escalating another employee's ticket requires manager role"}
    return {"ticket_id": ticket_id, "escalated_to": escalate_to, "status": "escalation_scheduled"}


TOOLS = {
    "lookup_ticket": lookup_ticket,
    "search_incident_logs": search_incident_logs,
    "query_sla_risk": query_sla_risk,
    "lookup_employee_directory": lookup_employee_directory,
    "retrieve_documents": retrieve_documents,
    "query_audit_log": query_audit_log,
    "schedule_escalation": schedule_escalation,
}
