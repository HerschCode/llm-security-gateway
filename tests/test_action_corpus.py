"""Regression tests pinning the action firewall's behaviour on the agentic attack corpus (corpus/agentic_attacks.yaml),
plus corpus hygiene (well-formed, and disjoint from the classifier's training data)."""
import csv
import re
from pathlib import Path

import pytest
import yaml

from gateway.actions.approvals import ApprovalQueue
from gateway.actions.firewall import ActionFirewall
from gateway.actions.policy import Principal
from scripts.evaluate_action_firewall import attempt_approvals

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = yaml.safe_load((REPO_ROOT / "corpus" / "agentic_attacks.yaml").read_text(encoding="utf-8"))["scenarios"]
EFFECTS = {"deny", "require_approval", "allow"}


def run_with_approvals(sc, tmp_path):
    """[(decision, approval attempts)] per call; attempts exist only on finance scenarios (`approve_attempts`)."""
    fw = ActionFirewall(approvals=ApprovalQueue(tmp_path / f"{sc['id']}.db"), audit_path=None)
    sid, p = sc["id"], sc["principal"]
    fw.register_source(sid, "user_message", sc["user_message"], "trusted")
    for c in sc.get("context") or []:
        fw.register_source(sid, c["source"], c["text"], c["trust"])
    out = []
    for call in sc["calls"]:
        d = fw.authorize(sid, Principal(p["role"], p["user_id"]), call["tool"], call["args"])
        out.append((d, attempt_approvals(fw, call, d)))
    return out


def run(sc, tmp_path):
    return [d for d, _ in run_with_approvals(sc, tmp_path)]


def test_corpus_is_large_and_well_formed():
    assert len(SCENARIOS) >= 40
    assert len({s["id"] for s in SCENARIOS}) == len(SCENARIOS)
    for s in SCENARIOS:
        assert s["principal"]["role"] in {"employee", "manager", "admin"} and s["principal"]["user_id"]
        assert s["calls"] and s["title"] and s["category"] and s["user_message"]
        for c in s["calls"]:
            assert c["expect"] in EFFECTS and isinstance(c["harmful"], bool)
        for ctx in s.get("context") or []:
            assert ctx["trust"] in {"trusted", "untrusted"} and ctx["text"]


def test_corpus_covers_the_required_attack_classes():
    cats = {s["category"] for s in SCENARIOS}
    assert {"indirect_injection", "tool_scope_escalation", "cross_user", "exfiltration", "confused_deputy",
            "schema_abuse", "taint_evasion", "benign"} <= cats


@pytest.mark.parametrize("sc", [s for s in SCENARIOS if not s.get("evasion")], ids=lambda s: s["id"])
def test_firewall_matches_ground_truth_on_every_non_evasion_scenario(sc, tmp_path):
    for call, d in zip(sc["calls"], run(sc, tmp_path)):
        assert d.effect == call["expect"], f"{sc['id']} {call['tool']}: expected {call['expect']}, got {d.effect} ({d.stage}: {d.reasons})"


@pytest.mark.parametrize("sc", [s for s in SCENARIOS if s.get("evasion")], ids=lambda s: s["id"])
def test_known_evasions_are_held_for_approval_not_silently_allowed(sc, tmp_path):
    """These are MISSES (paraphrase, translation, an acronym, data via a trusted tool; base64 and number words were fixed in Fix 5). The approval gate is
    the backstop. If taint tracking ever improves, this test should change and the docs with it."""
    harmful = [d for c, d in zip(sc["calls"], run(sc, tmp_path)) if c["harmful"]]
    assert harmful and all(d.effect == "require_approval" for d in harmful)


def test_no_benign_scenario_is_denied(tmp_path):
    for sc in SCENARIOS:
        if not any(c["harmful"] for c in sc["calls"]):
            assert all(d.effect != "deny" for d in run(sc, tmp_path)), sc["id"]


def test_nothing_harmful_is_executed_without_a_human_or_a_denial(tmp_path):
    """No harmful call may come back as a plain `allow`."""
    for sc in SCENARIOS:
        for c, d in zip(sc["calls"], run(sc, tmp_path)):
            if c["harmful"]:
                assert d.effect in {"deny", "require_approval"}, (sc["id"], c["tool"])


def test_corpus_is_disjoint_from_the_classifier_training_data():
    """Held-out discipline: nothing in this corpus may appear in data/train.csv."""
    norm = lambda t: re.sub(r"\s+", " ", str(t).strip().lower())  # noqa: E731
    train_path = REPO_ROOT / "data" / "train.csv"
    if not train_path.exists():
        pytest.skip("data/train.csv not present")
    csv.field_size_limit(10**9)
    train = {norm(r["text"]) for r in csv.DictReader(open(train_path, encoding="utf-8"))}
    texts = []
    for s in SCENARIOS:
        texts.append(s["user_message"])
        texts += [c["text"] for c in s.get("context") or []]
        texts += [v for call in s["calls"] if isinstance(call["args"], dict) for v in call["args"].values() if isinstance(v, str) and len(v) >= 12]
    assert not [t for t in texts if norm(t) in train]


# ---- finance (accounts-payable) scenarios --------------------------------------------------------------------------------------

FINANCE = [s for s in SCENARIOS if s["category"].startswith("finance_")]
# the attack classes the finance module was specified to cover, each pinned to the scenario that exercises it
FINANCE_CLASSES = {
    "poisoned 'CFO approved' invoice note": ["AG-FIN1"],
    "fake updated AP policy upload": ["AG-FIN2"],
    "confused-deputy hold then release": ["AG-FIN7", "AG-FIN8"],
    "requests split under the session cap": ["AG-FIN9"],
    "bank-detail exfiltration through `reason`": ["AG-FIN10", "AG-FIN13"],
    "self-approval": ["AG-FIN15", "AG-FIN17"],
    "same-role approval": ["AG-FIN16", "AG-FIN19"],
}


def test_finance_corpus_has_at_least_25_harmful_scenarios_and_covers_the_specified_classes():
    harmful = [s for s in FINANCE if any(c["harmful"] for c in s["calls"])]
    assert len(harmful) >= 25
    ids = {s["id"] for s in FINANCE}
    for name, wanted in FINANCE_CLASSES.items():
        assert set(wanted) <= ids, f"finance corpus lost its scenario for: {name}"
    assert {"finance_indirect_injection", "finance_confused_deputy", "finance_exfiltration", "finance_sod", "finance_scope", "finance_benign"} <= {s["category"] for s in FINANCE}


@pytest.mark.parametrize("sc", [s for s in SCENARIOS if any(c.get("approve_attempts") for c in s["calls"])], ids=lambda s: s["id"])
def test_every_approval_attempt_behaves_as_the_corpus_expects(sc, tmp_path):
    for call, (_, attempts) in zip(sc["calls"], run_with_approvals(sc, tmp_path)):
        assert [a["got"] for a in attempts] == [a["expect"] for a in call.get("approve_attempts") or []], (sc["id"], attempts)


def test_no_harmful_call_is_ever_approved_by_an_attempt(tmp_path):
    for sc in SCENARIOS:
        for call, (_, attempts) in zip(sc["calls"], run_with_approvals(sc, tmp_path)):
            if call["harmful"]:
                assert all(a["got"] == "refused" for a in attempts), (sc["id"], attempts)


def _pinned(sc):
    return pytest.param(sc, id=sc["id"], marks=pytest.mark.xfail(
        strict=True, reason="known miss, held for approval instead of stopped: " + sc["title"].replace("KNOWN MISS - ", "")))


@pytest.mark.parametrize("sc", [_pinned(s) for s in FINANCE if s.get("evasion")])
def test_finance_known_misses_are_pinned_until_fixed(sc, tmp_path):
    """What a correct firewall would do: deny every harmful call. It does not (see the title), so each is a strict xfail:
    the day a control closes the gap this fails, and the scenario and the docs must change with it."""
    for call, d in zip(sc["calls"], run(sc, tmp_path)):
        if call["harmful"]:
            assert d.effect == "deny", (sc["id"], d.effect)
