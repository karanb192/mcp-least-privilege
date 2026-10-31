#!/usr/bin/env python3
"""Inventory the real privilege surface of an MCP configuration.

Reads a Claude Code style mcp config ({"mcpServers": {...}}), starts every
stdio server in it exactly as the agent would, asks each for tools/list, and
prints what the agent could actually do: tool count per server, how many
tools are write-capable, destructive or open-world according to the server's
own annotations, and which tools carry no annotations at all (treat those as
write, destructive and open-world until proven otherwise).

The point: nobody reads 14 + 12 + 1 + 46 tool descriptions before saying
"add this server". This prints the number they should have asked for.

Usage: inventory.py [mcp.json] [--json] [--only SERVER,SERVER]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_probe import StdioClient  # noqa: E402


def classify(tool):
    ann = tool.get("annotations")
    if not ann:
        return "unannotated"
    if ann.get("readOnlyHint"):
        return "open-world read" if ann.get("openWorldHint") else "read"
    if ann.get("destructiveHint", True):
        return "destructive write"
    return "write"


def expand(value, env):
    if not isinstance(value, str):
        return value
    out = value
    for key, val in env.items():
        out = out.replace("${" + key + "}", val)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", nargs="?", default=".mcp.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--only", help="comma-separated server names")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()

    with open(args.config) as fh:
        servers = json.load(fh).get("mcpServers", {})
    only = set(args.only.split(",")) if args.only else None

    report = {}
    for name, spec in servers.items():
        if only and name not in only:
            continue
        if spec.get("type") not in (None, "stdio") or "command" not in spec:
            report[name] = {"skipped": f"not a stdio server ({spec.get('type') or spec.get('url')})"}
            continue
        env = {**os.environ, **{k: expand(v, os.environ) for k, v in (spec.get("env") or {}).items()}}
        command = [expand(spec["command"], env)] + [expand(a, env) for a in spec.get("args", [])]
        try:
            client = StdioClient(command, env=env, timeout=args.timeout)
            info = client.initialize()
            tools = client.list_tools()
            client.close()
        except Exception as exc:
            report[name] = {"error": str(exc)[:300], "command": command}
            continue
        classes = {}
        for t in tools:
            classes.setdefault(classify(t), []).append(t["name"])
        report[name] = {
            "server": f"{info.get('serverInfo', {}).get('name', '?')} {info.get('serverInfo', {}).get('version', '')}".strip(),
            "capabilities": sorted((info.get("capabilities") or {}).keys()),
            "tool_count": len(tools),
            "classes": {k: sorted(v) for k, v in classes.items()},
            "command": command,
        }

    if args.json:
        print(json.dumps(report, indent=2))
        return

    total = 0
    writes = 0
    for name, r in report.items():
        print(f"\n{name}: ", end="")
        if "skipped" in r:
            print(r["skipped"])
            continue
        if "error" in r:
            print(f"FAILED to start: {r['error']}")
            continue
        total += r["tool_count"]
        print(f"{r['server']}  ({r['tool_count']} tools, capabilities: {', '.join(r['capabilities'])})")
        print(f"  command: {' '.join(r['command'])}")
        for cls in ("read", "open-world read", "write", "destructive write", "unannotated"):
            names = r["classes"].get(cls)
            if not names:
                continue
            if cls in ("write", "destructive write", "unannotated"):
                writes += len(names)
            print(f"  {cls:<18} {len(names):>3}  {', '.join(names)}")
    print(f"\nprivilege surface: {total} tools across {len([r for r in report.values() if 'tool_count' in r])} servers, {writes} of them write-capable or unannotated")


if __name__ == "__main__":
    main()
