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

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = yaml.safe_load((REPO_ROOT / "corpus" / "agentic_attacks.yaml").read_text(encoding="utf-8"))["scenarios"]
EFFECTS = {"deny", "require_approval", "allow"}


def run(sc, tmp_path):
    fw = ActionFirewall(approvals=ApprovalQueue(tmp_path / f"{sc['id']}.db"), audit_path=None)
    sid, p = sc["id"], sc["principal"]
    fw.register_source(sid, "user_message", sc["user_message"], "trusted")
    for c in sc.get("context") or []:
        fw.register_source(sid, c["source"], c["text"], c["trust"])
    return [fw.authorize(sid, Principal(p["role"], p["user_id"]), call["tool"], call["args"]) for call in sc["calls"]]


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
    """These are MISSES by design (paraphrase, encoding, translation, data via a trusted tool). The approval gate is
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
