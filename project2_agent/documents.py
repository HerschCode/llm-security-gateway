"""
BEST-EFFORT RECONSTRUCTION -- READ THIS FIRST.

Everything in project2_agent/ is a guess, built from the one-paragraph
description of Project 2 in the build doc's context section: "a RAG-based ops
assistant -- agent with 7 structured tools, document retrieval with
citations, an eval corpus covering data/document/multi-step/adversarial
questions, a red-team corpus of prompt-injection attempts, tool-authorization
middleware, a refusal-policy decision table." None of Project 2's actual code,
document set, tool schemas, or real refusal wording is available in this
sandbox. This package invents plausible content shaped like that description,
in the same ops/SLA/incident domain as Projects 1 and 3, so there's a real,
functioning, non-trivial backend to test the gateway against -- not just the
much simpler `stub_ops_agent`. Expect to replace this wholesale once the real
Project 2 codebase is available; nothing here should be assumed to match it.

This module: a small in-memory document store with keyword-based retrieval
returning citation IDs, standing in for Project 2's real RAG index.
"""
from dataclasses import dataclass, field

DOCUMENTS = [
    {
        "doc_id": "DOC-001",
        "title": "SLA Policy Overview",
        "content": (
            "Standard SLA response time is 4 business hours for P1 incidents, "
            "24 hours for P2, and 72 hours for P3. Breaches are logged automatically "
            "and escalated to the on-call manager after 2x the SLA window elapses."
        ),
    },
    {
        "doc_id": "DOC-002",
        "title": "Incident Escalation Runbook",
        "content": (
            "P1 incidents must be escalated to the on-call engineer within 15 minutes "
            "of detection. If unacknowledged after 30 minutes, escalate to the "
            "engineering manager. Customer-facing communication is handled by support "
            "leads, not individual engineers."
        ),
    },
    {
        "doc_id": "DOC-003",
        "title": "Q2 2026 Postmortem: INC-4471",
        "content": (
            "INC-4471 was caused by a misconfigured firewall rule exposing the "
            "staging database. Root cause: a manual config change bypassed the "
            "standard review process. Remediation: added automated config validation "
            "to the deployment pipeline."
        ),
    },
    {
        "doc_id": "DOC-004",
        "title": "On-Call Rotation Policy",
        "content": (
            "On-call rotations run weekly, Monday to Monday. Engineers can request a "
            "swap up to 48 hours in advance via the on-call tool. Missed pages during "
            "an assigned rotation are reviewed by the engineering manager."
        ),
    },
    {
        "doc_id": "DOC-005",
        "title": "Data Access and Role Policy",
        "content": (
            "Employees can view their own tickets and public documentation. Managers "
            "can view their team's tickets, incident logs, and audit trails. Only "
            "admins can access org-wide employee records, compensation data, or "
            "unredacted audit logs across all teams."
        ),
    },
    {
        "doc_id": "DOC-006",
        "title": "Deployment Pipeline Overview",
        "content": (
            "Deployments go through staging, then a canary rollout to 5% of traffic, "
            "then full rollout. Rollbacks are automatic if error rates exceed 2% "
            "during canary. Schema changes require a separate approval step."
        ),
    },
]

# Extremely simple keyword-overlap retrieval -- a real RAG system would use
# embeddings; this is a deliberately basic stand-in, consistent with this
# whole package being a guess rather than a faithful reconstruction.


@dataclass
class RetrievedDoc:
    doc_id: str
    title: str
    snippet: str
    score: int


def retrieve(query: str, top_k: int = 2) -> list[RetrievedDoc]:
    query_words = set(query.lower().split())
    scored = []
    for doc in DOCUMENTS:
        doc_words = set((doc["title"] + " " + doc["content"]).lower().split())
        overlap = len(query_words & doc_words)
        if overlap > 0:
            scored.append((overlap, doc))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for score, doc in scored[:top_k]:
        results.append(RetrievedDoc(
            doc_id=doc["doc_id"], title=doc["title"],
            snippet=doc["content"][:200], score=score,
        ))
    return results
