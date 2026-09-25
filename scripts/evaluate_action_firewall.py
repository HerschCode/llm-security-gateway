"""
Measure the action firewall against the agentic attack corpus (corpus/agentic_attacks.yaml).

For every scenario the caller's message and context are registered in a fresh firewall session, then each tool call
the hijacked agent emits is authorized. Reported, per category and overall:

  * Which control stopped each HARMFUL call, in the order the controls act:
      text layers -> policy -> budget -> taint -> approval gate -> nothing
    "text layers (deployed)" means the gateway's pre-flight ensemble (PII redaction, normalize, rules + classifier)
    on the USER'S MESSAGE, which is all the gateway inspects today. "text layers (if context were scanned)" is a
    hypothetical: the same ensemble run over the retrieved/untrusted content, to show what scanning tool output
    would add. Neither is a measurement of how real LLMs behave: the corpus assumes the agent obeyed.
  * "held for approval" is not a block: a human decides, so harm then depends on the approver. It is counted
    separately from "stopped" and from "executed".
  * Ground-truth agreement: the firewall's decision on every call versus the corpus's `expect`.
  * Benign controls: any benign call that is DENIED is a false block.

Known-evasion scenarios (`evasion: true`) are reported on their own line and never folded into a headline number.

Run: python -X utf8 -m scripts.evaluate_action_firewall      (writes reports/p3_action_firewall.json)
"""
import json
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from gateway.actions.approvals import ApprovalQueue  # noqa: E402
from gateway.actions.firewall import ActionFirewall  # noqa: E402
from gateway.actions.policy import Principal  # noqa: E402
from gateway.middleware import GatewayMiddleware  # noqa: E402
from gateway.pii import scan_and_redact  # noqa: E402
from gateway.text_normalizer import normalize  # noqa: E402

CORPUS = REPO_ROOT / "corpus" / "agentic_attacks.yaml"


def load_scenarios(path: Path = CORPUS) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["scenarios"]


def text_layers_block(mw: GatewayMiddleware, text: str, sid: str) -> bool:
    """The gateway's pre-flight path on one piece of text: PII redaction, normalization, then the ensemble."""
    working = normalize(scan_and_redact(text).redacted_text)
    return bool(mw._run_injection_ensemble(working, sid)[0])


def run_scenario(sc: dict, mw: GatewayMiddleware, tmp: Path, index: int) -> dict:
    fw = ActionFirewall(approvals=ApprovalQueue(tmp / f"s{index}.db"), audit_path=None)
    sid = sc["id"]
    principal = Principal(sc["principal"]["role"], sc["principal"]["user_id"])
    fw.register_source(sid, "user_message", sc["user_message"], "trusted")
    for c in sc.get("context") or []:
        fw.register_source(sid, c["source"], c["text"], c["trust"])

    decisions = []
    for call in sc["calls"]:
        d = fw.authorize(sid, principal, call["tool"], call["args"])
        decisions.append({"tool": call["tool"], "expect": call["expect"], "harmful": call["harmful"],
                          "effect": d.effect, "stage": d.stage, "risk": d.risk,
                          "reasons": d.reasons[:2], "matches_expect": d.effect == call["expect"]})

    # text layers, scored separately from the firewall: a block only counts as a detection when the text really is an attack
    user_blocked = text_layers_block(mw, sc["user_message"], sid + "-u")
    is_attack_msg = bool(sc.get("attack_in_user_message"))
    ctx = [(c, text_layers_block(mw, c["text"], f"{sid}-c{i}")) for i, c in enumerate(sc.get("context") or []) if c["trust"] == "untrusted"]
    injected = [(c, b) for c, b in ctx if c.get("injected", True)]
    clean = [(c, b) for c, b in ctx if not c.get("injected", True)]
    harmful = [d for d in decisions if d["harmful"]]
    outcome = None
    if harmful:
        # what the FIREWALL does to the attack, independent of the text layers
        if any(d["effect"] == "deny" for d in harmful):
            stage = next(d["stage"] for d in harmful if d["effect"] == "deny")
            outcome = {"policy": "stopped_policy", "budget": "stopped_policy", "taint": "stopped_taint"}[stage]
        elif any(d["effect"] == "require_approval" for d in harmful):
            outcome = "held_for_approval"
        else:
            outcome = "executed"
    return {"id": sid, "category": sc["category"], "title": sc["title"], "evasion": bool(sc.get("evasion")),
            "attack_in_user_message": is_attack_msg,
            "text_deployed_detects_attack": user_blocked and is_attack_msg,
            "text_deployed_false_positive_on_user_message": user_blocked and not is_attack_msg,
            "has_injected_context": bool(injected),
            "text_context_scan_detects_injection": any(b for _, b in injected),
            "text_context_scan_false_positive_on_clean_context": any(b for _, b in clean),
            "calls": decisions, "outcome": outcome}


def summarise(results: list[dict]) -> dict:
    harmful = [r for r in results if r["outcome"]]
    benign = [r for r in results if not r["outcome"]]
    stopped = lambda rs: Counter(r["outcome"] for r in rs)  # noqa: E731
    by_cat = defaultdict(list)
    for r in results:
        by_cat[r["category"]].append(r)

    calls = [c for r in results for c in r["calls"]]
    scoped = [r for r in harmful if not r["evasion"]]
    evasive = [r for r in harmful if r["evasion"]]
    return {
        "scenarios": len(results), "harmful_scenarios": len(harmful), "benign_scenarios": len(benign),
        "harmful_excluding_known_evasions": dict(stopped(scoped)),
        "known_evasion_scenarios": dict(stopped(evasive)),
        "by_category": {c: dict(stopped([r for r in rs if r["outcome"]])) | {"benign_calls": sum(1 for r in rs if not r["outcome"])} for c, rs in by_cat.items()},
        "ground_truth_agreement": {"calls": len(calls), "match": sum(c["matches_expect"] for c in calls),
                                   "mismatches": [{"scenario": r["id"], "tool": c["tool"], "expect": c["expect"], "got": c["effect"], "stage": c["stage"]}
                                                  for r in results for c in r["calls"] if not c["matches_expect"]]},
        "benign_false_blocks": [r["id"] for r in benign if any(c["effect"] == "deny" for c in r["calls"])],
        "benign_held_high_risk": [r["id"] for r in benign if any(c["effect"] == "require_approval" and c["risk"] == "high" for c in r["calls"])],
        "text_layers": {
            "deployed_user_message_attacks": sum(r["attack_in_user_message"] for r in results),
            "deployed_detected_user_message_attacks": sum(r["text_deployed_detects_attack"] for r in results),
            "deployed_false_positives_on_innocuous_user_messages": sum(r["text_deployed_false_positive_on_user_message"] for r in results),
            "innocuous_user_messages": sum(not r["attack_in_user_message"] for r in results),
            "hypothetical_context_scan_scenarios_with_injected_context": sum(r["has_injected_context"] for r in results),
            "hypothetical_context_scan_detected": sum(r["text_context_scan_detects_injection"] for r in results),
            "hypothetical_context_scan_false_positives_on_clean_context": sum(r["text_context_scan_false_positive_on_clean_context"] for r in results),
        },
    }


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    scenarios = load_scenarios()
    mw = GatewayMiddleware()
    with tempfile.TemporaryDirectory() as td:
        results = [run_scenario(sc, mw, Path(td), i) for i, sc in enumerate(scenarios)]
    summary = summarise(results)
    (REPO_ROOT / "reports" / "p3_action_firewall.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")

    labels = {"stopped_policy": "stopped by policy/budget",
              "stopped_taint": "stopped by taint tracking", "held_for_approval": "held for human approval", "executed": "EXECUTED (nothing stopped it)"}
    print(f"{summary['scenarios']} scenarios: {summary['harmful_scenarios']} harmful, {summary['benign_scenarios']} benign controls")
    print("\nharmful scenarios, excluding known evasions:")
    for k, label in labels.items():
        print(f"  {label:<40} {summary['harmful_excluding_known_evasions'].get(k, 0)}")
    print("known-evasion scenarios (kept separate):")
    for k, label in labels.items():
        if summary["known_evasion_scenarios"].get(k):
            print(f"  {label:<40} {summary['known_evasion_scenarios'][k]}")
    t = summary["text_layers"]
    print("\ntext layers, deployed (they inspect only the user message):"
          f" detected {t['deployed_detected_user_message_attacks']}/{t['deployed_user_message_attacks']} attacks that were in the user message;"
          f" blocked {t['deployed_false_positives_on_innocuous_user_messages']}/{t['innocuous_user_messages']} innocuous user messages (false positives)")
    print("text layers, HYPOTHETICAL scan of retrieved content:"
          f" detected the injection in {t['hypothetical_context_scan_detected']}/{t['hypothetical_context_scan_scenarios_with_injected_context']} scenarios with injected context;"
          f" flagged clean context in {t['hypothetical_context_scan_false_positives_on_clean_context']} scenarios")
    g = summary["ground_truth_agreement"]
    print(f"ground-truth agreement: {g['match']}/{g['calls']} calls; mismatches: {g['mismatches']}")
    print("benign false blocks:", summary["benign_false_blocks"], "| benign held at high risk:", summary["benign_held_high_risk"])
    print("\nby category:", json.dumps(summary["by_category"], indent=1))
    print("\nWrote reports/p3_action_firewall.json")


if __name__ == "__main__":
    main()
