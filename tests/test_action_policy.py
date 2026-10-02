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


# ---- accounts-payable actions (operations-assistant's propose_payment_hold/propose_payment_release,
# both call this same tool -- see docs/decisions.md) --------------------------------------------------

HOLD = {"action": "hold_payment", "target": "CASE-4471", "reason": "C4 duplicate invoice: same vendor, same amount", "priority": "high"}
RELEASE = {"action": "release_payment", "target": "CASE-4471", "reason": "Duplicate resolved, see INV-2024-089", "priority": "normal"}


def test_hold_payment_matches_the_finance_hold_rule_and_does_not_require_role_separation(policy):
    r = policy.evaluate(MGR, "propose_intervention", HOLD)
    assert r.allowed and r.rule == "finance-hold" and not r.require_role_separation


def test_release_payment_matches_the_finance_release_rule_and_requires_role_separation(policy):
    r = policy.evaluate(MGR, "propose_intervention", RELEASE)
    assert r.allowed and r.rule == "finance-release" and r.require_role_separation


def test_release_payment_rejects_the_wrong_priority(policy):
    assert not policy.evaluate(MGR, "propose_intervention", {**RELEASE, "priority": "high"}).allowed


def test_hold_payment_rejects_the_wrong_priority(policy):
    assert not policy.evaluate(MGR, "propose_intervention", {**HOLD, "priority": "normal"}).allowed


def test_a_denied_action_names_every_closest_rule_not_only_the_first(policy):
    r = policy.evaluate(MGR, "propose_intervention", {**GOOD_PI, "action": "delete_supplier"})
    assert not r.allowed
    # finance-hold and manager-standard are each one failure away (the action); finance-release is two (action and priority), so it is left out
    assert [x.split("]")[0] for x in r.reasons] == ["[finance-hold", "[manager-standard"], r.reasons


@pytest.mark.parametrize("reason", [
    "remittance IBAN DE89370400440532013000", "pay to de89 3704 0044 0532 0130 00 now", "GB29NWBK60161331926819",
    "GB29 NWBK 6016 1331 9268 19", "FR1420041010050500013M02606",
])
def test_an_iban_in_the_reason_of_a_payment_request_is_rejected(policy, reason):
    for action, priority in (("hold_payment", "high"), ("release_payment", "normal")):
        assert not policy.evaluate(MGR, "propose_intervention", {"action": action, "target": "INV-1", "reason": reason, "priority": priority}).allowed


@pytest.mark.parametrize("reason", [
    "C4 duplicate invoice: same vendor, EUR 12,450, within 30 days", "Duplicate resolved, see INV-2024-089", "PO 4500012345 three-way match break on line 10",
    "Q3 review of FY24 exceptions for Kestrel Logistics", "FY24 exceptions for invoice 12345678", "ISO27001 audit finding 20240817 on vendor onboarding",
    "C5 payment-block override without segregation of duties", "Duplicate of invoice 2024-072 same amount 28 days apart", "CASE4471 vendor Kestrel 2024 2025 2026 2027",
    "vendor bank account change flagged on invoice",
])
def test_legitimate_payment_reasons_are_not_mistaken_for_an_iban(policy, reason):
    for action, priority in (("hold_payment", "high"), ("release_payment", "normal")):
        assert policy.evaluate(MGR, "propose_intervention", {"action": action, "target": "INV-1", "reason": reason, "priority": priority}).allowed


def test_ap_read_tools_are_manager_and_admin_only_with_checked_arguments(policy):
    for who in (MGR, ADM):
        assert policy.evaluate(who, "get_control_exceptions", {"control": "C4", "vendor": "Acme Supplies & Co.", "min_exposure": 5000.5, "top_n": 20}).allowed
        assert policy.evaluate(who, "get_control_summary", {}).allowed
        assert policy.evaluate(who, "get_working_capital_summary", {}).allowed
    for tool in ("get_control_exceptions", "get_control_summary", "get_working_capital_summary"):
        assert not policy.evaluate(EMP, tool, {}).allowed
    assert not policy.evaluate(MGR, "get_control_exceptions", {"control": "C9"}).allowed            # not a control id
    assert not policy.evaluate(MGR, "get_control_exceptions", {"top_n": 101}).allowed               # above the cap
    assert not policy.evaluate(MGR, "get_control_exceptions", {"min_exposure": -1}).allowed
    assert not policy.evaluate(MGR, "get_control_summary", {"vendor": "x"}).allowed                 # strict_args


def test_employee_may_not_hold_or_release_payments(policy):
    assert not policy.evaluate(EMP, "propose_intervention", HOLD).allowed
    assert not policy.evaluate(EMP, "propose_intervention", RELEASE).allowed


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
    ({"tools": {"t": {"kind": "write", "rules": [{"roles": ["admin"], "approval": "required", "require_role_separation": "yes"}]}}}, "boolean"),
    ({"tools": {"t": {"kind": "read", "rules": [{"roles": ["admin"], "require_role_separation": True}]}}}, "only applies to a rule with approval: required"),
])
def test_malformed_policy_fails_loudly_at_load_time(data, match):
    with pytest.raises(PolicyError, match=match):
        Policy(data)
