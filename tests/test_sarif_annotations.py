"""scripts/sarif_to_annotations.py: scanner findings become one readable annotation."""
import json

from scripts.sarif_to_annotations import annotation, escape, findings, main

SARIF = {"runs": [{"results": [
    {"ruleId": "python.lang.security.audit.dangerous-subprocess-use", "level": "warning",
     "message": {"text": "Detected subprocess\nfunction with user input"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "gateway/actions/mcp_proxy.py"}, "region": {"startLine": 210}}}]},
    {"ruleId": "dockerfile.security.missing-user", "level": "error", "message": {"text": "no USER"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 1}}}]},
]}]}


def test_each_result_becomes_one_line_with_level_rule_location_and_message():
    lines = findings(SARIF)
    assert lines == [
        "warning python.lang.security.audit.dangerous-subprocess-use gateway/actions/mcp_proxy.py:210 Detected subprocess function with user input",
        "error dockerfile.security.missing-user Dockerfile:1 no USER",
    ]


def test_the_annotation_is_a_single_workflow_command_line():
    text = annotation("Semgrep", findings(SARIF))
    assert text.startswith("::notice title=Semgrep%3A 2 findings::")
    assert "\n" not in text and "%0A" in text          # the two findings are joined with an escaped newline


def test_escaping_follows_the_workflow_command_rules():
    assert escape("100%\r\nx") == "100%25%0D%0Ax"
    assert escape("a:b,c", prop=True) == "a%3Ab%2Cc" and escape("a:b,c") == "a:b,c"


def test_a_missing_or_empty_file_never_fails_the_step(tmp_path, capsys):
    assert main([str(tmp_path / "nope.sarif"), "--title", "Semgrep"]) == 0
    assert "no SARIF file" in capsys.readouterr().out
    empty = tmp_path / "e.sarif"
    empty.write_text(json.dumps({"runs": [{"results": []}]}), encoding="utf-8")
    assert main([str(empty)]) == 0
    assert "0 findings" in capsys.readouterr().out
