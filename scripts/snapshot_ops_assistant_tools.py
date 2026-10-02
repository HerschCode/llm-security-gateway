"""
Snapshot (or check) the MCP tool list that operations-assistant exposes, so this repo's policy cannot drift from it silently.

The gateway's action policy is default-deny: an MCP tool the policy does not list is hidden from `tools/list` and denied on
call, and a tool argument the matching rule does not declare is rejected (strict_args). When operations-assistant adds a tool
or an argument and this repo is not told, the feature is silently dead behind the gateway. tests/test_policy_covers_ops_assistant_tools.py
compares config/tool_policies.yaml with the committed snapshot; this script keeps the snapshot honest.

CI cannot see operations-assistant (a separate repository), so the check against the live server is a manual step:

    python -X utf8 scripts/snapshot_ops_assistant_tools.py            # rewrite tests/fixtures/ops_assistant_mcp_tools.json
    python -X utf8 scripts/snapshot_ops_assistant_tools.py --check    # exit 1 if the committed snapshot is stale

It imports operations-assistant's own `src.mcp_server` in-process, so run it with an interpreter that has that repository's
dependencies (its tests' interpreter). `--p2-dir` / $P2_DIR point at the checkout (default: ../../0_Project/operations-assistant).
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "ops_assistant_mcp_tools.json"
DEFAULT_P2 = REPO_ROOT.parents[1] / "0_Project" / "operations-assistant"


def live_tools(p2_dir: Path) -> dict:
    sys.path.insert(0, str(p2_dir))
    os.chdir(p2_dir)
    from src import mcp_server  # operations-assistant's own package
    tools = asyncio.run(mcp_server.mcp.list_tools())

    def schema(t) -> dict:  # the attribute name differs between MCP SDK versions
        return getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or getattr(t, "parameters", None) or {}

    return {t.name: {"properties": sorted(schema(t).get("properties", {})), "required": sorted(schema(t).get("required", []))}
            for t in sorted(tools, key=lambda t: t.name)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p2-dir", type=Path, default=Path(os.environ.get("P2_DIR", DEFAULT_P2)))
    ap.add_argument("--check", action="store_true", help="compare with the committed snapshot instead of writing it")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    if not (args.p2_dir / "src" / "mcp_server.py").exists():
        sys.exit(f"operations-assistant not found at {args.p2_dir} (set --p2-dir or P2_DIR)")

    snapshot = {"source": "operations-assistant src.mcp_server, FastMCP list_tools()", "tools": live_tools(args.p2_dir)}
    if args.check:
        committed = json.loads(FIXTURE.read_text(encoding="utf-8"))
        if committed["tools"] == snapshot["tools"]:
            print(f"snapshot is current ({len(snapshot['tools'])} tools)")
            return
        old, new = set(committed["tools"]), set(snapshot["tools"])
        print("snapshot is STALE")
        print("  added in operations-assistant:  ", sorted(new - old))
        print("  removed in operations-assistant:", sorted(old - new))
        print("  argument changes:               ", sorted(n for n in old & new if committed["tools"][n] != snapshot["tools"][n]))
        sys.exit(1)
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(REPO_ROOT)}: {', '.join(snapshot['tools'])}")


if __name__ == "__main__":
    main()
