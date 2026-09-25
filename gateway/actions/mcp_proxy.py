"""
MCP proxy mode: the action firewall in front of any MCP server.

    MCP client (Claude Desktop, an agent runtime)  <-stdio->  this proxy  <-stdio->  upstream MCP server

The proxy is a JSON-RPC message filter (`MCPFirewallProxy`) plus a stdio bridge (`run_stdio`). It
  * `tools/call` requests   -> ActionFirewall.authorize(): allow (forwarded), deny (answered here with an
                               error result, never forwarded), or require_approval (queued; answered with a
                               "held for approval" result and executed later, by the proxy, once a human approves);
  * `tools/call` results    -> registered as taint sources (trust from the policy), so a later write whose
                               arguments were copied from an untrusted result is caught;
  * `resources/read` and `prompts/get` results -> registered as untrusted;
  * `tools/list` results    -> filtered to the tools the caller's role may use (default-deny hides unlisted tools);
  * everything else (initialize, ping, notifications, ...) passes through untouched.

Transport: newline-delimited JSON-RPC over stdio, which is what Claude Desktop and most MCP hosts spawn. HTTP
transports (SSE, streamable HTTP) are NOT implemented. stdout carries protocol only; diagnostics go to stderr.

Limits, stated plainly:
  * Identity (`--role`, `--user-id`) is asserted by whoever launches the proxy (the host's config), not
    authenticated per call. The MCP stdio transport has no identity.
  * The proxy sees tool results but not the user's chat message, so it cannot tell "the user typed this" from
    "a document said this" when both appear in a result. That errs toward suspicion (a tainted `target` on a
    write is denied); pass trusted context through the HTTP API (`/gateway/actions/sources`) if the host can.
  * Approved actions are executed by the proxy process that received the request. If it exits before approval,
    the request stays `approved` with `execution_status` NULL (visible in the queue), and is not run.

Usage (host config):  python -m gateway.actions.mcp_proxy --role manager --user-id mona -- python -m src.mcp_server
"""
import argparse
import json
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

from gateway.actions.api import get_firewall
from gateway.actions.firewall import ActionFirewall
from gateway.actions.policy import Principal

_INTERNAL_PREFIX = "fw-"     # ids the proxy uses for approved actions it executes itself; clients may not use it

# Methods that pass through untouched. Everything else is blocked (default-deny at the protocol level), because a
# method introduced by a newer protocol revision could execute tools without going through `tools/call`.
_PASS_METHODS = ("initialize", "ping", "notifications/", "tools/list", "resources/", "prompts/", "completion/", "logging/")


@dataclass
class Routed:
    to_upstream: list[dict] = field(default_factory=list)
    to_client: list[dict] = field(default_factory=list)


def _result_text(result: dict | None) -> str:
    """Text of an MCP tool/resource/prompt result (all text parts joined) for taint registration."""
    if not isinstance(result, dict):
        return ""
    parts = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(item["text"])
    for item in result.get("contents") or []:              # resources/read
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(item["text"])
    for m in result.get("messages") or []:                 # prompts/get
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            parts.append(c["text"])
    if result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], default=str))
    return "\n".join(parts)


def _tool_result(request_id, text: str, is_error: bool, firewall_meta: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": is_error, "_meta": {"actionFirewall": firewall_meta}}}


class MCPFirewallProxy:
    def __init__(self, firewall: ActionFirewall, principal: Principal, session_id: str | None = None):
        self.fw = firewall
        self.principal = principal
        self.session = session_id or f"mcp-{uuid.uuid4().hex[:8]}"
        self._inflight: dict = {}          # forwarded request id -> (method, tool_or_uri)
        self._internal: dict[str, str] = {}   # proxy-issued execution id -> approval id
        self._lock = threading.Lock()

    # ---- client -> upstream ------------------------------------------------------------------------

    def from_client(self, msg) -> Routed:
        if isinstance(msg, list):                       # JSON-RPC batch
            out = Routed()
            for m in msg:
                r = self.from_client(m)
                out.to_upstream += r.to_upstream
                out.to_client += r.to_client
            return out
        if not isinstance(msg, dict) or "method" not in msg:
            return Routed(to_upstream=[msg])            # a response to a server-initiated request, or junk: pass through
        method, mid = msg["method"], msg.get("id")

        if isinstance(mid, str) and mid.startswith(_INTERNAL_PREFIX):
            return Routed(to_client=[{"jsonrpc": "2.0", "id": mid, "error": {"code": -32600, "message": "request ids starting with 'fw-' are reserved"}}])

        if method == "tools/call" and mid is None:
            print("[mcp-proxy] dropped a tools/call sent as a notification (no id): it would run unchecked", file=sys.stderr)
            return Routed()

        if method == "tools/call":
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            name, args = params.get("name"), params.get("arguments")
            if not isinstance(name, str) or not (args is None or isinstance(args, dict)):
                # never evaluate a coerced copy of malformed input while forwarding the original
                return Routed(to_client=[{"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "tools/call requires a string tool name and object arguments"}}])
            args = args or {}
            d = self.fw.authorize(self.session, self.principal, name, args, source="mcp")
            meta = {"effect": d.effect, "stage": d.stage, "risk": d.risk, "approval_id": d.approval_id}
            if d.effect == "deny":
                return Routed(to_client=[_tool_result(mid, "Blocked by the action firewall: " + "; ".join(d.reasons), True, meta)])
            if d.effect == "require_approval":
                text = (f"HELD FOR HUMAN APPROVAL (id {d.approval_id}, risk {d.risk}). The action has NOT been executed; "
                        "a reviewer must approve it first." + (" Reason: " + "; ".join(d.reasons) if d.reasons else ""))
                return Routed(to_client=[_tool_result(mid, text, False, meta)])
            with self._lock:
                self._inflight[mid] = ("tools/call", name)
            return Routed(to_upstream=[msg])

        if not method.startswith(_PASS_METHODS) and method != "tools/call":
            if mid is None:
                return Routed()
            return Routed(to_client=[{"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method {method!r} is blocked by the action firewall (not on the allowlist)"}}])

        if method in ("tools/list", "resources/read", "prompts/get") and mid is not None:
            with self._lock:
                self._inflight[mid] = (method, (msg.get("params") or {}).get("uri") or (msg.get("params") or {}).get("name"))
        return Routed(to_upstream=[msg])

    # ---- upstream -> client ------------------------------------------------------------------------

    def from_upstream(self, msg) -> Routed:
        if isinstance(msg, list):
            out = Routed()
            for m in msg:
                r = self.from_upstream(m)
                out.to_upstream += r.to_upstream
                out.to_client += r.to_client
            return out
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            return Routed(to_client=[msg])              # notifications and server-initiated requests pass through
        mid = msg["id"]

        with self._lock:
            approval_id = self._internal.pop(mid, None) if isinstance(mid, str) else None
            tracked = self._inflight.pop(mid, None)

        if approval_id is not None:                     # result of an approved action WE executed
            result = msg.get("result")
            ok = "error" not in msg and not (isinstance(result, dict) and result.get("isError"))
            text = _result_text(result) or json.dumps(msg.get("error") or {}, default=str)
            self.fw.approvals.mark_executed(approval_id, ok, text)
            return Routed()                             # the client never asked for it: swallow

        if tracked is None or "error" in msg:
            return Routed(to_client=[msg])
        method, what = tracked
        result = msg.get("result")
        if method == "tools/call":
            self.fw.observe_result(self.session, str(what), _result_text(result))
        elif method in ("resources/read", "prompts/get"):
            self.fw.register_source(self.session, f"{method}:{what}", _result_text(result), "untrusted")
        elif method == "tools/list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
            visible = [t for t in result["tools"] if isinstance(t, dict) and self.fw.policy.visible_to(self.principal.role, t.get("name", ""))]
            msg = {**msg, "result": {**result, "tools": visible}}
        return Routed(to_client=[msg])

    # ---- approved actions ------------------------------------------------------------------------------

    def poll_executions(self) -> list[dict]:
        """Requests to send upstream for approvals granted since the last poll. The policy is evaluated again at
        execution time (the policy or the requester's role may have changed while the request was pending)."""
        out = []
        for row in self.fw.approvals.claim_approved("mcp", self.session):
            requester = Principal(row["requester_role"], row["requester_id"])
            recheck = self.fw.policy.evaluate(requester, row["tool"], row["args"])
            if not recheck.allowed:
                self.fw.approvals.mark_executed(row["id"], False, "not executed: policy no longer allows it (" + "; ".join(recheck.reasons) + ")")
                continue
            rid = f"{_INTERNAL_PREFIX}{row['id']}"
            with self._lock:
                self._internal[rid] = row["id"]
            out.append({"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": row["tool"], "arguments": row["args"]}})
        return out


# ---- stdio bridge ---------------------------------------------------------------------------------------

def run_stdio(upstream_cmd: list[str], proxy: MCPFirewallProxy, poll_interval: float = 0.5, stdin=None, stdout=None):
    """Spawn the upstream server and pump newline-delimited JSON-RPC both ways through `proxy`."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    up = subprocess.Popen(upstream_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
                          text=True, encoding="utf-8", bufsize=1)
    write_lock = threading.Lock()
    stop = threading.Event()

    def send(stream, msg):
        with write_lock:
            stream.write(json.dumps(msg) + "\n")
            stream.flush()

    def upstream_reader():
        for line in up.stdout:
            if not line.strip():
                continue
            try:
                routed = proxy.from_upstream(json.loads(line))
            except json.JSONDecodeError:
                print(f"[mcp-proxy] dropped non-JSON line from upstream: {line[:80]!r}", file=sys.stderr)
                continue
            for m in routed.to_client:
                send(stdout, m)
        stop.set()

    def executor():
        while not stop.wait(poll_interval):
            for m in proxy.poll_executions():
                try:
                    send(up.stdin, m)
                except (BrokenPipeError, ValueError):
                    return

    threading.Thread(target=upstream_reader, daemon=True).start()
    threading.Thread(target=executor, daemon=True).start()
    try:
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                send(stdout, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue                                   # never forward unparseable data upstream
            routed = proxy.from_client(msg)
            for m in routed.to_client:
                send(stdout, m)
            for m in routed.to_upstream:
                send(up.stdin, m)
    finally:
        stop.set()
        try:
            up.stdin.close()
        except OSError:
            pass
        up.wait(timeout=5)


def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(description="Action-firewall MCP proxy (stdio). Everything after `--` is the upstream server command.")
    ap.add_argument("--role", default="employee", choices=["employee", "manager", "admin"])
    ap.add_argument("--user-id", default="unknown")
    ap.add_argument("--session-id", default=None)
    ap.add_argument("--poll-interval", type=float, default=0.5)
    args, rest = ap.parse_known_args(argv)
    if rest and rest[0] == "--":
        rest = rest[1:]
    if not rest:
        ap.error("give the upstream server command after `--`")
    proxy = MCPFirewallProxy(get_firewall(), Principal(args.role, args.user_id), args.session_id)
    print(f"[mcp-proxy] role={args.role} user={args.user_id} session={proxy.session} upstream={rest}", file=sys.stderr)
    run_stdio(rest, proxy, args.poll_interval)


if __name__ == "__main__":
    main()
