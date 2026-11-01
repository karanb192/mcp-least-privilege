#!/usr/bin/env python3
"""Derive a least-privilege boundary policy from an observed behaviour trace.

Input: one or more JSONL traces written by boundary.py while an agent did a
task under the unrestricted policy. Output: a deny-by-default policy that
allows exactly the tools the agent used, confined to the directory prefixes
and hosts it touched, plus a record of every tool the server offered at the
time (so later runs can detect server-side drift too).

Usage:
  derive_policy.py TRACE.jsonl [TRACE2.jsonl ...] [--server LABEL] [--out POLICY.json]
"""
import argparse
import datetime as dt
import json
import os
import sys


def load_events(paths):
    for p in paths:
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)


def top_dir(rel):
    """First path component: 'docs/overview.md' -> 'docs', 'docs' -> 'docs',
    '' (the root itself) -> ''. A bare file name at the root stays as itself,
    which allows exactly that file."""
    if rel.startswith("OUTSIDE_ROOT:"):
        return None
    return rel.split("/", 1)[0]


def derive(events, server):
    calls = [e for e in events if e.get("event") == "call" and e.get("server") == server and e.get("decision") == "allow"]
    lists = [e for e in events if e.get("event") == "tools_list" and e.get("server") == server]
    if not calls:
        sys.exit(f"no allowed calls for server '{server}' in the trace")

    tools = {}
    all_read_only = True
    for e in calls:
        spec = tools.setdefault(e["tool"], {"_paths": set(), "_hosts": set(), "_path_key": None, "_url_key": None})
        ann = e.get("annotations") or {}
        if not ann.get("readOnlyHint"):
            all_read_only = False
        for p in e.get("paths", []):
            d = top_dir(p)
            if d is not None:
                spec["_paths"].add(d)
        for h in e.get("hosts", []):
            spec["_hosts"].add(h)
        for k in e.get("arg_keys", []):
            base = k.split(".")[-1].split("[")[0]
            if base in ("path", "paths", "repo_path", "source", "destination") and spec["_path_key"] is None:
                spec["_path_key"] = base
            if base == "url" and spec["_url_key"] is None:
                spec["_url_key"] = base

    out_tools = {}
    for name, spec in sorted(tools.items()):
        rule = {}
        if spec["_paths"] and spec["_path_key"]:
            rule[spec["_path_key"]] = {"under": sorted(spec["_paths"])}
        if spec["_hosts"] and spec["_url_key"]:
            rule[spec["_url_key"]] = {"schemes": ["https"], "hosts": sorted(spec["_hosts"]), "max_query_len": 64}
        out_tools[name] = {"args": rule} if rule else {}

    offered = {}
    for e in lists:
        for t in e.get("offered", []):
            offered[t["name"]] = t.get("annotations") or {}

    policy = {
        "name": f"derived-{server}",
        "description": f"Derived by derive_policy.py on {dt.date.today().isoformat()} from {len(calls)} observed calls. Review before use: a trace shows what the agent did, not what it should be allowed to do.",
        "default": "deny",
        "require_read_only_hint": all_read_only,
        "tools": out_tools,
        "baseline_offered": {k: offered[k] for k in sorted(offered)},
    }
    return policy


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("traces", nargs="+")
    parser.add_argument("--server", help="server label to derive for (default: the only one in the trace)")
    parser.add_argument("--out", help="write the policy here instead of stdout")
    args = parser.parse_args()

    events = list(load_events(args.traces))
    servers = sorted({e.get("server") for e in events if e.get("event") == "call"})
    server = args.server
    if server is None:
        if len(servers) != 1:
            sys.exit(f"trace has calls for {servers}; pick one with --server")
        server = servers[0]

    policy = derive(events, server)
    text = json.dumps(policy, indent=2) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"wrote {args.out}: {len(policy['tools'])} tools allowed out of {len(policy['baseline_offered'])} offered", file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
