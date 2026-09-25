"""
Human approval queue for actions the firewall will not run on its own.

SQLite (stdlib) rather than an in-memory dict because the queue has to be shared between
processes: the stdio MCP proxy is a separate process from the gateway web app that shows the
dashboard and receives approve/deny clicks. WAL mode allows one writer and many readers safely.

Controls enforced here (not in the HTTP layer, so every caller gets them):
  * only manager/admin may decide;
  * separation of duties: the approver may not be the requester;
  * a decision is final: a non-pending request cannot be decided again;
  * pending requests expire (default 24 h) and then cannot be approved;
  * execution is tracked separately from approval (`execution_status`), so an approved request that
    was never executed (proxy down) is visible rather than silently lost.

Not implemented: authenticating the approver. `approver_id` / role are asserted by the caller; the
HTTP layer protects the endpoints with a shared token (see api.py). Real deployments should put SSO in front.
"""
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from gateway.actions.policy import Principal

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "logs" / "approvals.db"
APPROVER_ROLES = {"manager", "admin"}
DEFAULT_TTL_SECONDS = 24 * 3600
MAX_PENDING = 200          # refuse to queue more: the authorize endpoint is unauthenticated on the public demo

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, created_at REAL NOT NULL, session_id TEXT NOT NULL,
    requester_role TEXT NOT NULL, requester_id TEXT NOT NULL, tool TEXT NOT NULL,
    args_json TEXT NOT NULL, reasons_json TEXT NOT NULL, evidence_json TEXT NOT NULL,
    risk TEXT NOT NULL, source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',          -- pending | approved | denied
    decided_by TEXT, decided_role TEXT, decided_at REAL, note TEXT,
    execution_status TEXT, execution_result TEXT      -- NULL | claimed | executed | failed
)"""


class ApprovalError(Exception):
    """A decision was refused. Subclasses tell the HTTP layer which status code applies."""


class ApprovalNotFound(ApprovalError):
    pass


class ApprovalForbidden(ApprovalError):
    """Wrong role, or the requester tried to decide their own request."""


class ApprovalConflict(ApprovalError):
    """Already decided, or expired."""


class ApprovalQueue:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.path = str(db_path)
        self.ttl = ttl_seconds
        self._lock = threading.Lock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(_SCHEMA)

    @contextmanager
    def _conn(self):
        """A short-lived connection: committed on success, rolled back on error, always closed."""
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    @staticmethod
    def _row(r: sqlite3.Row | None) -> dict | None:
        if r is None:
            return None
        d = dict(r)
        for k in ("args", "reasons", "evidence"):
            d[k] = json.loads(d.pop(f"{k}_json"))
        return d

    def enqueue(self, session_id: str, principal: Principal, tool: str, args: dict, reasons: list[str],
                evidence: dict, risk: str, source: str = "http") -> str:
        approval_id = f"apr_{uuid.uuid4().hex[:10]}"
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO approvals (id, created_at, session_id, requester_role, requester_id, tool, args_json,"
                " reasons_json, evidence_json, risk, source) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (approval_id, time.time(), session_id, principal.role, principal.user_id, tool,
                 json.dumps(args, default=str), json.dumps(reasons), json.dumps(evidence, default=str), risk, source),
            )
        return approval_id

    def count_pending(self) -> int:
        cutoff = time.time() - self.ttl
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM approvals WHERE status='pending' AND created_at>=?", (cutoff,)).fetchone()[0]

    def get(self, approval_id: str) -> dict | None:
        with self._conn() as c:
            return self._row(c.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone())

    def list_requests(self, status: str | None = None, limit: int = 100) -> list[dict]:
        q, params = "SELECT * FROM approvals", []
        if status:
            q += " WHERE status=?"
            params.append(status)
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as c:
            rows = [self._row(r) for r in c.execute(q, params).fetchall()]
        now = time.time()
        for r in rows:
            r["expired"] = r["status"] == "pending" and now - r["created_at"] > self.ttl
        return rows

    def decide(self, approval_id: str, approve: bool, approver: Principal, note: str = "") -> dict:
        if approver.role not in APPROVER_ROLES:
            raise ApprovalForbidden(f"role {approver.role!r} may not decide approvals")
        with self._lock, self._conn() as c:
            row = c.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None:
                raise ApprovalNotFound(f"approval {approval_id!r} not found")
            if row["status"] != "pending":
                raise ApprovalConflict(f"approval {approval_id!r} is already {row['status']}")
            if time.time() - row["created_at"] > self.ttl:
                raise ApprovalConflict(f"approval {approval_id!r} has expired")
            if approver.user_id.strip().lower() == row["requester_id"].strip().lower():
                raise ApprovalForbidden("separation of duties: the requester may not decide their own request")
            c.execute("UPDATE approvals SET status=?, decided_by=?, decided_role=?, decided_at=?, note=? WHERE id=?",
                      ("approved" if approve else "denied", approver.user_id, approver.role, time.time(), note, approval_id))
        return self.get(approval_id)

    # ---- execution bookkeeping (used by the process that holds the upstream connection) ----------

    def claim_approved(self, source: str, session_id: str | None = None) -> list[dict]:
        """Atomically claim approved-but-unexecuted requests so exactly one executor runs each."""
        with self._lock, self._conn() as c:
            q = "SELECT id FROM approvals WHERE status='approved' AND execution_status IS NULL AND source=?"
            params = [source]
            if session_id:
                q += " AND session_id=?"
                params.append(session_id)
            ids = [r["id"] for r in c.execute(q, params).fetchall()]
            for i in ids:
                c.execute("UPDATE approvals SET execution_status='claimed' WHERE id=?", (i,))
        return [self.get(i) for i in ids]

    def mark_executed(self, approval_id: str, ok: bool, result: str):
        with self._lock, self._conn() as c:
            c.execute("UPDATE approvals SET execution_status=?, execution_result=? WHERE id=?",
                      ("executed" if ok else "failed", result[:2000], approval_id))
