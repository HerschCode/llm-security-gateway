"""Tests for the MCP proxy: message-level behaviour in-process, and one real stdio subprocess run."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from gateway.actions import demo_upstream
from gateway.actions.approvals import ApprovalQueue
from gateway.actions.firewall import ActionFirewall
from gateway.actions.mcp_proxy import MCPFirewallProxy
from gateway.actions.policy import Principal

REPO_ROOT = Path(__file__).resolve().parents[1]
MGR = Principal("manager", "mona")
MGR2 = Principal("manager", "max")
EMP = Principal("employee", "alice")


@pytest.fixture
def effects(tmp_path, monkeypatch):
    path = tmp_path / "effects.jsonl"
    monkeypatch.setenv("DEMO_UPSTREAM_EFFECTS", str(path))
    return path


def make_proxy(tmp_path, principal=MGR):
    fw = ActionFirewall(approvals=ApprovalQueue(tmp_path / "a.db"), audit_path=tmp_path / "actions.jsonl")
    return MCPFirewallProxy(fw, principal, session_id="t1")


def pump(proxy, msg):
    """Client message through the proxy; anything forwarded upstream is answered by the demo server and
    fed back through the proxy. Returns (messages to the client, list of upstream messages seen)."""
    routed = proxy.from_client(msg)
    to_client, upstream_seen = list(routed.to_client), list(routed.to_upstream)
    for m in routed.to_upstream:
        resp = demo_upstream.handle(m)
        if resp is not None:
            to_client += proxy.from_upstream(resp).to_client
    return to_client, upstream_seen


def call(i, name, args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


def text_of(resp):
    return resp["result"]["content"][0]["text"]


def read_effects(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


PI = {"action": "escalate_case", "target": "CASE-1", "reason": "SLA breach risk", "priority": "high"}


def test_tools_list_is_filtered_by_role_and_hides_unlisted_tools(tmp_path):
    names = lambda proxy: {t["name"] for t in pump(proxy, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})[0][0]["result"]["tools"]}
    assert names(make_proxy(tmp_path, EMP)) == {"get_sla_metrics", "search_policy_documents"}
    assert names(make_proxy(tmp_path, MGR)) == {"get_sla_metrics", "search_policy_documents", "propose_intervention"}   # never delete_all_records


def test_allowed_read_is_forwarded_and_its_result_returned(tmp_path):
    out, seen = pump(make_proxy(tmp_path), call(2, "get_sla_metrics", {"segment": "category"}))
    assert len(seen) == 1 and "breach_rate" in text_of(out[0]) and out[0]["result"]["isError"] is False


def test_unlisted_destructive_tool_is_blocked_and_never_reaches_upstream(tmp_path, effects):
    out, seen = pump(make_proxy(tmp_path), call(3, "delete_all_records", {"period": "2026-Q3"}))
    assert seen == [] and out[0]["result"]["isError"] is True and "default deny" in text_of(out[0])
    assert read_effects(effects) == []


def test_poisoned_document_then_write_is_blocked_by_taint(tmp_path, effects):
    proxy = make_proxy(tmp_path)
    doc, _ = pump(proxy, call(4, "search_policy_documents", {"query": "escalation addendum"}))
    assert "ZX-9000" in text_of(doc[0])                                     # the poisoned text reached the client...
    out, seen = pump(proxy, call(5, "propose_intervention", {**PI, "target": "ZX-9000"}))   # ...and the agent obeyed it
    assert seen == [] and out[0]["result"]["isError"] is True
    assert out[0]["result"]["_meta"]["actionFirewall"]["stage"] == "taint"
    assert read_effects(effects) == []


def test_clean_write_is_held_then_executed_only_after_a_second_person_approves(tmp_path, effects):
    proxy = make_proxy(tmp_path)
    out, seen = pump(proxy, call(6, "propose_intervention", PI))
    assert seen == [] and "HELD FOR HUMAN APPROVAL" in text_of(out[0]) and out[0]["result"]["isError"] is False
    approval_id = out[0]["result"]["_meta"]["actionFirewall"]["approval_id"]
    assert read_effects(effects) == [] and proxy.poll_executions() == []          # nothing runs before approval

    proxy.fw.approvals.decide(approval_id, True, MGR2)
    (execution,) = proxy.poll_executions()
    assert execution["params"]["name"] == "propose_intervention" and execution["id"].startswith("fw-")
    reply = proxy.from_upstream(demo_upstream.handle(execution))
    assert reply.to_client == []                                                      # swallowed: the client never asked
    assert read_effects(effects) == [{"tool": "propose_intervention", "args": PI}]
    assert proxy.fw.approvals.get(approval_id)["execution_status"] == "executed"
    assert proxy.poll_executions() == []                                              # exactly once


def test_denied_request_is_never_executed(tmp_path, effects):
    proxy = make_proxy(tmp_path)
    approval_id = pump(proxy, call(7, "propose_intervention", PI))[0][0]["result"]["_meta"]["actionFirewall"]["approval_id"]
    proxy.fw.approvals.decide(approval_id, False, MGR2, "no")
    assert proxy.poll_executions() == [] and read_effects(effects) == []


def test_policy_is_rechecked_at_execution_time(tmp_path, effects):
    proxy = make_proxy(tmp_path)
    approval_id = pump(proxy, call(8, "propose_intervention", PI))[0][0]["result"]["_meta"]["actionFirewall"]["approval_id"]
    proxy.fw.approvals.decide(approval_id, True, MGR2)
    proxy.fw.policy.tools["propose_intervention"]["rules"] = [r for r in proxy.fw.policy.tools["propose_intervention"]["rules"] if "manager" not in r["roles"]]
    assert proxy.poll_executions() == []
    row = proxy.fw.approvals.get(approval_id)
    assert row["execution_status"] == "failed" and "no longer allows" in row["execution_result"]
    assert read_effects(effects) == []


@pytest.mark.parametrize("bad_args", ["a string", ["a", "list"], 0, ""])
def test_non_object_arguments_are_rejected_not_coerced(tmp_path, bad_args):
    out, seen = pump(make_proxy(tmp_path), {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "get_sla_metrics", "arguments": bad_args}})
    assert seen == [] and out[0]["error"]["code"] == -32602


def test_tools_call_sent_as_a_notification_is_dropped(tmp_path, effects):
    out, seen = pump(make_proxy(tmp_path), {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "propose_intervention", "arguments": PI}})
    assert out == [] and seen == [] and read_effects(effects) == []


def test_reserved_ids_and_unknown_methods_are_refused(tmp_path):
    proxy = make_proxy(tmp_path)
    assert pump(proxy, {"jsonrpc": "2.0", "id": "fw-apr_x", "method": "ping"})[0][0]["error"]["code"] == -32600
    blocked = pump(proxy, {"jsonrpc": "2.0", "id": 10, "method": "tasks/execute", "params": {}})
    assert blocked[1] == [] and blocked[0][0]["error"]["code"] == -32601


def test_protocol_basics_pass_through(tmp_path):
    proxy = make_proxy(tmp_path)
    init, seen = pump(proxy, {"jsonrpc": "2.0", "id": 11, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    assert init[0]["result"]["serverInfo"]["name"] == "demo-ops-upstream" and len(seen) == 1
    assert pump(proxy, {"jsonrpc": "2.0", "id": 12, "method": "ping"})[0][0]["result"] == {}
    assert pump(proxy, {"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == []


def test_batch_requests_are_each_checked(tmp_path, effects):
    out, seen = pump(make_proxy(tmp_path), [call(13, "delete_all_records", {}), call(14, "get_sla_metrics", {})])
    assert len(seen) == 1 and {r["id"] for r in out} == {13, 14}
    assert read_effects(effects) == []


# ---- real stdio subprocess ---------------------------------------------------------------------------------------

def test_end_to_end_over_real_stdio(tmp_path):
    env = {**os.environ, "GATEWAY_APPROVALS_DB": str(tmp_path / "e2e.db"), "GATEWAY_ACTIONS_AUDIT": str(tmp_path / "e2e.jsonl"),
           "DEMO_UPSTREAM_EFFECTS": str(tmp_path / "e2e_effects.jsonl"), "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "gateway.actions.mcp_proxy", "--role", "manager", "--user-id", "mona", "--session-id", "e2e",
         "--poll-interval", "0.1", "--", sys.executable, "-m", "gateway.actions.demo_upstream"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", cwd=REPO_ROOT, env=env)

    def rpc(msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    try:
        assert rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})["result"]["serverInfo"]
        listed = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        assert "delete_all_records" not in {t["name"] for t in listed}
        assert rpc(call(3, "delete_all_records", {}))["result"]["isError"] is True
        assert "ZX-9000" in text_of(rpc(call(4, "search_policy_documents", {"query": "addendum"})))
        assert rpc(call(5, "propose_intervention", {**PI, "target": "ZX-9000"}))["result"]["isError"] is True     # tainted
        held = rpc(call(6, "propose_intervention", PI))
        approval_id = held["result"]["_meta"]["actionFirewall"]["approval_id"]
        queue = ApprovalQueue(tmp_path / "e2e.db")
        queue.decide(approval_id, True, MGR2)                                     # a different process approves
        deadline = time.time() + 15
        while time.time() < deadline and (queue.get(approval_id)["execution_status"] != "executed"):
            time.sleep(0.2)
        assert queue.get(approval_id)["execution_status"] == "executed"
        assert read_effects(tmp_path / "e2e_effects.jsonl") == [{"tool": "propose_intervention", "args": PI}]
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
