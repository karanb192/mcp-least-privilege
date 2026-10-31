#!/usr/bin/env python3
"""Run one task headlessly in Claude Code with a per-task tool allowlist.

A task manifest (tasks/*.json) names the prompt, the tools the task needs and
the tools it must never get. This runner turns that into a `claude -p` command:

  --grant task   (default) the manifest's allowlist: least privilege per task
  --grant agent  the per-agent grant most deployments ship with: every tool of
                 every connected server, so the blast radius of an injection is
                 the whole server

Calls outside the allowlist are denied by Claude Code itself (permission mode
dontAsk), before any MCP server sees them. The command is printed before it
runs so the audience can read the exact flags.

Usage: run_task.py tasks/summarize-docs.json [--grant task|agent]
                   [--mcp-config mcp/raw.json] [--model NAME] [--max-turns N] [--dry-run]
"""
import argparse
import json
import os
import shlex
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("task")
    parser.add_argument("--grant", choices=["task", "agent"], default="task")
    parser.add_argument("--mcp-config", default="mcp/raw.json")
    parser.add_argument("--model", default=os.environ.get("CLAUDE_MODEL"))
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--no-gate", action="store_true", help="switch the tier gate hook (demo 4) off for this run, so only the allowlist or the boundary is under test")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with open(args.task) as fh:
        task = json.load(fh)
    with open(args.mcp_config) as fh:
        servers = list(json.load(fh)["mcpServers"].keys())

    cmd = ["claude", "-p", task["prompt"], "--strict-mcp-config", "--mcp-config", args.mcp_config,
           "--permission-mode", "dontAsk", "--max-turns", str(args.max_turns), "--output-format", "text"]
    if args.model:
        cmd += ["--model", args.model]
    if args.grant == "agent":
        cmd += ["--allowedTools"] + [f"mcp__{s}__*" for s in servers]
        built_in_denies = [t for t in task.get("disallowed_tools", []) if not t.startswith("mcp__")]
        if built_in_denies:
            cmd += ["--disallowedTools"] + built_in_denies
    else:
        cmd += ["--allowedTools"] + task["allowed_tools"]
        if task.get("disallowed_tools"):
            cmd += ["--disallowedTools"] + task["disallowed_tools"]

    gate = "OFF (TIER_GATE_OFF=1: the agent as most deployments run it)" if args.no_gate else "on (hooks/tier_gate.py via .claude/settings.json)"
    print(f"# task: {task['name']}   grant: {args.grant}   servers: {', '.join(servers)}   tier gate: {gate}", file=sys.stderr)
    print("$ " + " ".join(shlex.quote(c) if c != task["prompt"] else '"<prompt>"' for c in cmd), file=sys.stderr)
    print(file=sys.stderr)
    if args.dry_run:
        return 0

    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")}
    if args.no_gate:
        env["TIER_GATE_OFF"] = "1"
    try:
        return subprocess.call(cmd, env=env)
    except FileNotFoundError:
        print("claude not found on PATH: install Claude Code or use the replay mode of this demo", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
