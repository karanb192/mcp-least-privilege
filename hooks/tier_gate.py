#!/usr/bin/env python3
"""PreToolUse hook for Claude Code: approval keyed to privilege tier.

Reads the tool call Claude Code is about to make (JSON on stdin), finds the
first tier in policies/tiers.json whose patterns match the tool name, and
answers with that tier's decision:

  allow  the call runs with no prompt (tier 0: read-only)
  ask    Claude Code shows its normal permission prompt, with the tier's
         reason in it (tier 1: local, reversible writes)
  deny   the call never runs; the reason is fed back to the model
         (tier 2: irreversible, or leaves the laptop)

Tools that match no tier get the policy's default (ask). Built-in tools
(Bash, Edit, ...) are left to Claude Code's own permission rules: this hook
only speaks for MCP tools. Every decision is appended to
traces/live/hook-decisions.jsonl so the drift tooling can see it.

Standard library only. Exit code is always 0; the decision travels in JSON,
which is the documented way to allow, ask or deny from a PreToolUse hook.
"""
import datetime as dt
import fnmatch
import json
import os
import sys


def repo_root():
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return env
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    if os.environ.get("TIER_GATE_OFF"):
        # Demos 1, 3 and 5 switch the gate off on purpose to show an agent
        # running the way most deployments ship it. Silence means "no opinion"
        # and Claude Code falls back to its own permission rules.
        return
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return
    tool = payload.get("tool_name", "")
    if not tool.startswith("mcp__"):
        return

    root = repo_root()
    policy_path = os.environ.get("TIER_POLICY", os.path.join(root, "policies", "tiers.json"))
    with open(policy_path) as fh:
        policy = json.load(fh)

    decision, tier_name, reason = policy.get("default", "ask"), "unmatched", policy.get("default_reason", "no tier matched this tool")
    for tier in policy["tiers"]:
        if any(fnmatch.fnmatchcase(tool, pat) for pat in tier["match"]):
            decision, tier_name, reason = tier["decision"], tier["name"], tier.get("reason", "")
            break

    label = f"[tier gate] {tier_name}: {decision}. {reason}".strip()
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": label,
        }
    }
    print(json.dumps(out, indent=2))

    log_path = os.path.join(root, "traces", "live", "hook-decisions.jsonl")
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as fh:
            fh.write(json.dumps({
                "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "tool": tool,
                "tier": tier_name,
                "decision": decision,
                "input_keys": sorted((payload.get("tool_input") or {}).keys()),
            }) + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    main()
