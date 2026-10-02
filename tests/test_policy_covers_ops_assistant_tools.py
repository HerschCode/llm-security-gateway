"""The action policy and operations-assistant's MCP server must not drift apart silently.

The policy is default-deny, so a tool operations-assistant exposes but this repo does not list is hidden and denied behind the
gateway, and an argument the matching rule does not declare is rejected (strict_args). That is how the payment tools and three
finance read tools went dead behind the gateway on 2026-09-29 with every test green: nothing compared the two repositories.

CI cannot import operations-assistant, so this compares config/tool_policies.yaml with a committed snapshot of its MCP tool list
(tests/fixtures/ops_assistant_mcp_tools.json). `python scripts/snapshot_ops_assistant_tools.py --check` compares the snapshot
with the live server; run it, and regenerate the snapshot, whenever operations-assistant's tools change.
"""
import json
from pathlib import Path

import pytest

from gateway.actions.policy import Policy

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((REPO_ROOT / "tests" / "fixtures" / "ops_assistant_mcp_tools.json").read_text(encoding="utf-8"))["tools"]
POLICY = Policy.load()

# Tools operations-assistant exposes that this policy deliberately does not govern yet. Each is a known, pinned miss: the
# test is xfail(strict), so it fails the moment the policy covers the tool or the snapshot drops it, and the entry must go.
KNOWN_UNCOVERED = {
    "propose_payment_hold": "duplicate of propose_intervention(action=hold_payment); operations-assistant is removing it (one write path per privileged action)",
    "propose_payment_release": "duplicate of propose_intervention(action=release_payment); operations-assistant is removing it (one write path per privileged action)",
}

# In the policy but not an operations-assistant MCP tool: an illustrative user-scoped read used to show `equals: $principal.user_id`.
POLICY_ONLY = {"get_my_cases"}


def _marked(name):
    return pytest.param(name, marks=pytest.mark.xfail(strict=True, reason=KNOWN_UNCOVERED[name])) if name in KNOWN_UNCOVERED else name


@pytest.mark.parametrize("tool", [_marked(n) for n in sorted(SNAPSHOT)])
def test_every_operations_assistant_tool_has_a_policy_entry(tool):
    assert POLICY.tool(tool) is not None, f"{tool!r} is exposed by operations-assistant but has no entry in config/tool_policies.yaml (default-deny hides it)"


@pytest.mark.parametrize("tool", sorted(n for n in SNAPSHOT if n not in KNOWN_UNCOVERED))
def test_every_argument_a_tool_declares_is_permitted_by_some_rule(tool):
    spec = POLICY.tool(tool)
    permitted = {a for rule in spec["rules"] for a in (rule.get("args") or {})}
    missing = set(SNAPSHOT[tool]["properties"]) - permitted
    assert not missing, f"{tool}: operations-assistant accepts {sorted(missing)} but no rule declares them, so strict_args rejects every call that uses them"


@pytest.mark.parametrize("tool", sorted(n for n in SNAPSHOT if n not in KNOWN_UNCOVERED))
def test_every_required_argument_is_required_or_optional_consistently(tool):
    """A rule must not make an argument mandatory that operations-assistant treats as optional: that would deny valid calls."""
    optional = set(SNAPSHOT[tool]["properties"]) - set(SNAPSHOT[tool]["required"])
    for rule in POLICY.tool(tool)["rules"]:
        for arg, constraint in (rule.get("args") or {}).items():
            assert not (arg in optional and constraint.get("required")), f"{tool}/{rule.get('name')}: {arg!r} is optional upstream but required by the policy"


def test_no_policy_entry_names_a_tool_operations_assistant_does_not_have():
    stale = set(POLICY.tools) - set(SNAPSHOT) - POLICY_ONLY
    assert not stale, f"policy entries for tools operations-assistant no longer exposes: {sorted(stale)}"


def test_the_pinned_misses_are_still_real():
    """If a KNOWN_UNCOVERED tool disappeared from the snapshot, its entry above is dead weight: delete it."""
    assert set(KNOWN_UNCOVERED) <= set(SNAPSHOT), f"remove from KNOWN_UNCOVERED: {sorted(set(KNOWN_UNCOVERED) - set(SNAPSHOT))}"
