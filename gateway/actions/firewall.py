"""
The action firewall: one decision per tool call, from three independent controls.

    authorize(session, principal, tool, args)
      1. policy   default-deny capability check with argument constraints      -> deny
      2. taint    write-tool arguments copied from untrusted text              -> deny or flag (per policy)
      3. approval write tools (and any rule marked approval: required)         -> require_approval

Every decision is appended to an audit log (JSONL) with string arguments passed through the same PII redaction
the rest of the gateway uses. The firewall never executes anything: it says allow / deny / require_approval, and
the caller (an agent runtime or the MCP proxy) acts on it. That keeps it usable both as an HTTP policy decision
point and inside the proxy.

Session state (taint spans, write counts) is in memory and bounded, per session id. Like the gateway's rate
limiter, it does not survive a restart or span multiple instances; the approval queue does (SQLite).
"""
import json
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from gateway.actions.approvals import MAX_PENDING, ApprovalQueue
from gateway.actions.policy import Policy, Principal
from gateway.actions.taint import TaintTracker
from gateway.pii import scan_and_redact

DEFAULT_AUDIT_PATH = Path(__file__).resolve().parents[2] / "logs" / "actions.jsonl"
MAX_SESSIONS = 200


@dataclass
class Decision:
    effect: str                         # "allow" | "deny" | "require_approval"
    tool: str
    reasons: list[str] = field(default_factory=list)
    rule: str | None = None
    risk: str = "low"                   # "low" | "medium" | "high"
    tainted: list[dict] = field(default_factory=list)
    approval_id: str | None = None
    stage: str | None = None            # which control decided: "policy" | "taint" | "budget" | "approval" | None (allow)

    def to_dict(self) -> dict:
        return asdict(self)


class _Session:
    def __init__(self):
        self.taint = TaintTracker()
        self.writes: dict[str, int] = {}


class ActionFirewall:
    def __init__(self, policy: Policy | None = None, approvals: ApprovalQueue | None = None,
                 audit_path: Path | str | None = DEFAULT_AUDIT_PATH):
        self.policy = policy or Policy.load()
        self.approvals = approvals or ApprovalQueue()
        self.audit_path = Path(audit_path) if audit_path else None
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()

    # ---- context registration ---------------------------------------------------------------------

    def _session(self, session_id: str) -> _Session:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                s = self._sessions[session_id] = _Session()
                if len(self._sessions) > MAX_SESSIONS:
                    self._sessions.popitem(last=False)
            else:
                self._sessions.move_to_end(session_id)
            return s

    def register_source(self, session_id: str, kind: str, text: str, trust: str):
        """Register text that entered the agent's context (user message, document, upload, ...)."""
        self._session(session_id).taint.add(kind, text, trust)

    def observe_result(self, session_id: str, tool: str, result_text: str):
        """Register a tool result; its trust comes from the policy (unknown tools: untrusted)."""
        self.register_source(session_id, f"tool_result:{tool}", result_text, self.policy.output_trust(tool))

    # ---- decision -----------------------------------------------------------------------------------

    def authorize(self, session_id: str, principal: Principal, tool: str, args: dict, source: str = "http") -> Decision:
        if not isinstance(args, dict):
            decision = Decision("deny", tool, ["arguments must be an object"], risk="high", stage="policy")
        else:
            decision = self._decide(session_id, principal, tool, args, source)
        self._audit(session_id, principal, tool, args, decision)
        return decision

    def _decide(self, session_id, principal, tool, args, source) -> Decision:
        result = self.policy.evaluate(principal, tool, args)
        if not result.allowed:
            return Decision("deny", tool, result.reasons, result.rule, risk="high", stage="policy")

        spec = self.policy.tool(tool)
        session = self._session(session_id)

        cap = spec.get("max_per_session")
        if cap is not None and session.writes.get(tool, 0) >= cap:
            return Decision("deny", tool, [f"per-session limit of {cap} calls to {tool!r} reached"], result.rule,
                            risk="high", stage="budget")

        tainted, risk, reasons = [], "low", []
        reactions = spec.get("taint") or {}
        if reactions:
            for f in session.taint.analyze(args, list(reactions)):
                if not f.tainted:
                    continue
                reaction = reactions[f.field.split(".")[0].split("[")[0]]
                tainted.append({"field": f.field, "reaction": reaction, "score": f.score,
                                "source": f.source_kind, "snippet": f.snippet})
                reasons.append(f"argument {f.field!r} was copied from untrusted content ({f.source_kind})")
                risk = "high"
            if any(t["reaction"] == "deny" for t in tainted):
                return Decision("deny", tool, reasons, result.rule, risk="high", tainted=tainted, stage="taint")

        if result.approval == "required":
            if self.approvals.count_pending() >= MAX_PENDING:
                return Decision("deny", tool, [f"the approval queue is full ({MAX_PENDING} pending); nothing more can be queued"],
                                result.rule, risk="high", stage="budget")
            if spec["kind"] == "write":
                session.writes[tool] = session.writes.get(tool, 0) + 1
            risk = "high" if risk == "high" else "medium"
            evidence = {"tainted": tainted, "policy_rule": result.rule}
            approval_id = self.approvals.enqueue(
                session_id, principal, tool, args, reasons or ["write action requires human approval"], evidence, risk, source)
            return Decision("require_approval", tool, reasons or ["write action requires human approval"], result.rule,
                            risk=risk, tainted=tainted, approval_id=approval_id, stage="approval")

        return Decision("allow", tool, reasons, result.rule, risk=risk, tainted=tainted)

    # ---- audit ---------------------------------------------------------------------------------------

    @staticmethod
    def _redact(value):
        if isinstance(value, str):
            return scan_and_redact(value[:300]).redacted_text
        if isinstance(value, dict):
            return {k: ActionFirewall._redact(v) for k, v in value.items()}
        if isinstance(value, list):
            return [ActionFirewall._redact(v) for v in value[:20]]
        return value

    def _audit(self, session_id, principal, tool, args, d: Decision):
        if not self.audit_path:
            return
        record = {"timestamp": time.time(), "session_id": session_id, "user_id": principal.user_id, "role": principal.role,
                  "tool": tool, "effect": d.effect, "stage": d.stage, "rule": d.rule, "risk": d.risk, "reasons": d.reasons,
                  "tainted": [{k: t[k] for k in ("field", "reaction", "source")} for t in d.tainted],
                  "approval_id": d.approval_id, "args": self._redact(args if isinstance(args, dict) else {})}
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
