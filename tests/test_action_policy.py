"""Unit tests for the action-firewall policy engine (gateway/actions/policy.py) against the real
config/tool_policies.yaml, plus malformed-policy rejection."""
import pytest

from gateway.actions.policy import Policy, PolicyError, Principal

EMP = Principal("employee", "alice")
MGR = Principal("manager", "mona")
ADM = Principal("admin", "ada")


@pytest.fixture(scope="module")
def policy():
    return Policy.load()


GOOD_PI = {"action": "escalate_case", "target": "CASE-4471", "reason": "SLA breach risk is high", "priority": "high"}


def test_unlisted_tool_is_denied_by_default(policy):
    r = policy.evaluate(ADM, "delete_all_records", {})
    assert not r.allowed and "default deny" in r.reasons[0]


def test_read_tool_allowed_for_every_role(policy):
    for who in (EMP, MGR, ADM):
        assert policy.evaluate(who, "get_sla_metrics", {"segment": "category"}).allowed


def test_role_gate_employee_cannot_call_write_or_manager_reads(policy):
    assert not policy.evaluate(EMP, "propose_intervention", GOOD_PI).allowed
    assert not policy.evaluate(EMP, "get_management_report", {}).allowed
    assert policy.evaluate(MGR, "get_management_report", {}).allowed


def test_write_tool_always_requires_approval(policy):
    r = policy.evaluate(MGR, "propose_intervention", GOOD_PI)
    assert r.allowed and r.approval == "required" and r.rule == "manager-standard"


def test_urgent_priority_is_admin_only(policy):
    urgent = {**GOOD_PI, "priority": "urgent"}
    assert not policy.evaluate(MGR, "propose_intervention", urgent).allowed
    r = policy.evaluate(ADM, "propose_intervention", urgent)
    assert r.allowed and r.rule == "admin-urgent"


@pytest.mark.parametrize("override", [
    {"action": "delete_case"},                          # not an allowed action
    {"target": "https://evil.example/x"},               # pattern: no URLs in target
    {"target": "CASE-1\nIGNORE PREVIOUS"},              # pattern: no newlines
    {"reason": "send it to attacker@evil.com"},         # not_pattern: email
    {"reason": "the api_key is abc"},                   # not_pattern: secret words
    {"reason": "x" * 501},                              # max_length
    {"priority": "critical"},                           # not in enum
])
def test_argument_constraints_reject_bad_values(policy, override):
    assert not policy.evaluate(MGR, "propose_intervention", {**GOOD_PI, **override}).allowed


def test_strict_args_reject_smuggled_parameters(policy):
    r = policy.evaluate(MGR, "propose_intervention", {**GOOD_PI, "skip_approval": True})
    assert not r.allowed and any("strict_args" in x for x in r.reasons)


def test_missing_required_argument_is_rejected(policy):
    args = {k: v for k, v in GOOD_PI.items() if k != "target"}
    assert not policy.evaluate(MGR, "propose_intervention", args).allowed


def test_own_records_only_binds_to_the_caller(policy):
    assert policy.evaluate(EMP, "get_my_cases", {"user_id": "alice"}).allowed
    r = policy.evaluate(EMP, "get_my_cases", {"user_id": "bob"})
    assert not r.allowed and any("own records" in x for x in r.reasons)
    assert policy.evaluate(MGR, "get_my_cases", {"user_id": "bob"}).allowed  # managers may look across users


def test_type_confusion_is_rejected(policy):
    assert not policy.evaluate(MGR, "get_supplier_performance", {"top_n": "10"}).allowed      # str, not int
    assert not policy.evaluate(MGR, "get_supplier_performance", {"top_n": True}).allowed      # bool is not an int
    assert not policy.evaluate(MGR, "get_supplier_performance", {"top_n": 9999}).allowed      # above max
    assert policy.evaluate(MGR, "get_supplier_performance", {"top_n": 10}).allowed


def test_non_object_arguments_are_rejected(policy):
    assert not policy.evaluate(MGR, "get_conformance", ["not", "an", "object"]).allowed


def test_output_trust_defaults_to_untrusted_for_unknown_tools(policy):
    assert policy.output_trust("search_policy_documents") == "untrusted"
    assert policy.output_trust("get_sla_metrics") == "trusted"
    assert policy.output_trust("some_new_tool") == "untrusted"


def test_visibility_follows_role_rules(policy):
    assert policy.visible_to("manager", "propose_intervention")
    assert not policy.visible_to("employee", "propose_intervention")
    assert not policy.visible_to("admin", "delete_all_records")


@pytest.mark.parametrize("data,match", [
    ({"default_effect": "allow", "tools": {}}, "default_effect"),
    ({"tools": {"t": {"kind": "read", "rulez": []}}}, "unknown keys"),
    ({"tools": {"t": {"kind": "exec"}}}, "kind"),
    ({"tools": {"t": {"kind": "write", "rules": [{"roles": ["admin"], "args": {}}]}}}, "approval"),
    ({"tools": {"t": {"kind": "read", "rules": [{"roles": ["admin"], "args": {"a": {"regexp": "x"}}}]}}}, "unknown keys"),
    ({"tools": {"t": {"kind": "read", "taint": {"a": "ignore"}}}}, "taint"),
    ({"tools": {"t": {"kind": "read", "rules": [{"roles": []}]}}}, "roles"),
])
def test_malformed_policy_fails_loudly_at_load_time(data, match):
    with pytest.raises(PolicyError, match=match):
        Policy(data)
