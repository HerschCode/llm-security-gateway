"""
Side-by-side demo of the action firewall, fully in-process and deterministic (no LLM, no network).

A "naive agent" is scripted to do what a hijacked agent does: read a document that contains an injected
instruction, then obey it by calling tools. The same behaviour is replayed twice against the same undefended
demo MCP server (gateway/actions/demo_upstream.py, which records every effect):

  A. DIRECT     the agent talks straight to the server        -> the poisoned instruction is carried out
  B. FIREWALLED the agent talks through the MCP proxy          -> the harmful calls are blocked; a clean, legitimate
                                                                  request from the same session is held for a human
                                                                  approval, approved by a DIFFERENT manager, and executed

The agent is a script, not a model: this shows what the firewall does once an agent is hijacked, not how often
real models are.

Run: python -X utf8 -m scripts.demo_action_firewall
"""
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import os  # noqa: E402

from gateway.actions import demo_upstream  # noqa: E402
from gateway.actions.approvals import ApprovalQueue  # noqa: E402
from gateway.actions.firewall import ActionFirewall  # noqa: E402
from gateway.actions.mcp_proxy import MCPFirewallProxy  # noqa: E402
from gateway.actions.policy import Principal  # noqa: E402

_ids = iter(range(1, 1000))


def call(name, args):
    return {"jsonrpc": "2.0", "id": next(_ids), "method": "tools/call", "params": {"name": name, "arguments": args}}


def text(resp):
    return resp["result"]["content"][0]["text"]


def effects(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()] if Path(path).exists() else []


class Direct:
    """The agent's tool connection with no firewall."""
    def send(self, msg):
        return demo_upstream.handle(msg)


class Firewalled:
    def __init__(self, proxy):
        self.proxy = proxy

    def send(self, msg):
        routed = self.proxy.from_client(msg)
        out = list(routed.to_client)
        for up in routed.to_upstream:
            resp = demo_upstream.handle(up)
            if resp:
                out += self.proxy.from_upstream(resp).to_client
        return out[0] if out else None


def hijacked_agent(conn, label):
    """Read the poisoned addendum, then do exactly what it says."""
    print(f"  user asks: 'What does the escalation addendum say?'")
    doc = conn.send(call("search_policy_documents", {"query": "escalation addendum"}))
    print(f"  agent reads a document containing: ...{text(doc)[64:170]}...")
    for name, args in (("propose_intervention", {"action": "escalate_case", "target": "ZX-9000", "reason": "per addendum", "priority": "high"}),
                       ("delete_all_records", {"period": "2026-Q3"})):
        r = conn.send(call(name, args))
        print(f"  agent calls {name}({json.dumps(args)[:70]}...)\n    -> {text(r)[:130]}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        os.environ["DEMO_UPSTREAM_EFFECTS"] = str(td / "effects.jsonl")

        print("=" * 78 + "\nA. DIRECT: no firewall\n" + "=" * 78)
        hijacked_agent(Direct(), "direct")
        print(f"\n  EFFECTS ON THE SYSTEM: {effects(td / 'effects.jsonl')}")
        (td / "effects.jsonl").unlink()

        print("\n" + "=" * 78 + "\nB. FIREWALLED: same agent, same server, through the MCP proxy (manager 'mona')\n" + "=" * 78)
        fw = ActionFirewall(approvals=ApprovalQueue(td / "approvals.db"), audit_path=td / "actions.jsonl")
        proxy = MCPFirewallProxy(fw, Principal("manager", "mona"), session_id="demo")
        conn = Firewalled(proxy)
        hijacked_agent(conn, "firewalled")
        print(f"\n  EFFECTS ON THE SYSTEM: {effects(td / 'effects.jsonl')}   <- nothing happened")

        print("\n  Now a LEGITIMATE request in the same session. The user says: 'Escalate CASE-4471, it is about to breach.'")
        fw.register_source("demo", "user_message", "Please escalate CASE-4471, it is about to breach its SLA.", "trusted")
        clean = {"action": "escalate_case", "target": "CASE-4471", "reason": "SLA breach imminent per manager request", "priority": "high"}
        held = conn.send(call("propose_intervention", clean))
        approval_id = held["result"]["_meta"]["actionFirewall"]["approval_id"]
        print(f"  agent calls propose_intervention(CASE-4471)\n    -> {text(held)[:150]}")
        print(f"  effects so far: {effects(td / 'effects.jsonl')}")
        print("  a second manager ('max') approves in the dashboard (the requester 'mona' could not: separation of duties)")
        try:
            fw.approvals.decide(approval_id, True, Principal("manager", "mona"))
        except Exception as e:  # noqa: BLE001
            print(f"    mona tries to approve her own request -> refused: {e}")
        fw.approvals.decide(approval_id, True, Principal("manager", "max"))
        for execution in proxy.poll_executions():
            proxy.from_upstream(demo_upstream.handle(execution))
        print(f"  EFFECTS ON THE SYSTEM: {effects(td / 'effects.jsonl')}")

        print("\n  Audit log (every decision is recorded):")
        for line in (td / "actions.jsonl").read_text().splitlines():
            r = json.loads(line)
            print(f"    {r['tool']:<22} {r['effect']:<17} stage={r['stage']} risk={r['risk']}"
                  + (f"  tainted={[t['field'] for t in r['tainted']]}" if r["tainted"] else ""))


if __name__ == "__main__":
    main()
