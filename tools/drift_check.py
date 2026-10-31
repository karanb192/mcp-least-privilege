#!/usr/bin/env python3
"""Diff a run's trace against a derived policy and fail on privilege drift.

Two kinds of drift are reported:

  agent drift   the agent called a tool, path prefix or host the policy does
                not allow. Reported whether or not the boundary blocked it at
                run time: an attempt is drift, a success is a misconfiguration.
  server drift  the server now offers tools that were not there when the
                policy was derived, or a tool's annotations changed (for
                example a tool that was read-only no longer says so). This is
                how a routine `npx -y` upgrade widens your privilege surface.

Exit 0 and "no drift" when the run stayed inside the policy, exit 1 and a
DRIFT report otherwise. In GitHub Actions the findings also come out as
::error:: annotations.

Usage:
  drift_check.py --policy POLICY.json TRACE.jsonl [TRACE2.jsonl ...]
"""
import argparse
import fnmatch
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_events(paths):
    for p in paths:
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)


def under_any(rel, dirs):
    for d in dirs:
        d = d.strip("/")
        if d == "" or rel == d or rel.startswith(d + "/"):
            return True
    return False


def host_ok(host, allowed):
    for pat in allowed:
        pat = pat.lower()
        if pat.startswith("*.") and (host == pat[2:] or host.endswith(pat[1:])):
            return True
        if host == pat:
            return True
    return False


def allowed_tool(policy, name):
    return any(fnmatch.fnmatchcase(name, pat) for pat in policy.get("tools", {}))


def rules_for(policy, name):
    merged = {}
    for pat, spec in policy.get("tools", {}).items():
        if fnmatch.fnmatchcase(name, pat):
            merged.update((spec or {}).get("args", {}) or {})
    return merged


def check(policy, events, server):
    findings = []
    calls = [e for e in events if e.get("event") == "call" and (server is None or e.get("server") == server)]
    for e in calls:
        tool = e["tool"]
        runtime = "blocked at run time" if e.get("decision") == "deny" else "ALLOWED at run time"
        if not allowed_tool(policy, tool):
            findings.append(("agent", f"tool '{tool}' is not in the policy ({runtime})"))
            continue
        rules = rules_for(policy, tool)
        unders = [r["under"] for r in rules.values() if isinstance(r, dict) and "under" in r]
        if unders:
            allowed_dirs = [d for u in unders for d in u]
            for p in e.get("paths", []):
                if p.startswith("OUTSIDE_ROOT:") or not under_any(p, allowed_dirs):
                    findings.append(("agent", f"tool '{tool}' touched '{p}', policy allows {allowed_dirs} ({runtime})"))
        hosts_rules = [r["hosts"] for r in rules.values() if isinstance(r, dict) and "hosts" in r]
        if hosts_rules:
            allowed_hosts = [h for hr in hosts_rules for h in hr]
            for h in e.get("hosts", []):
                if not host_ok(h, allowed_hosts):
                    findings.append(("agent", f"tool '{tool}' reached host '{h}', policy allows {allowed_hosts} ({runtime})"))

    baseline = policy.get("baseline_offered") or {}
    if baseline:
        for e in events:
            if e.get("event") != "tools_list" or (server is not None and e.get("server") != server):
                continue
            offered = {t["name"]: t.get("annotations") or {} for t in e.get("offered", [])}
            new = sorted(set(offered) - set(baseline))
            gone = sorted(set(baseline) - set(offered))
            if new:
                findings.append(("server", f"server now offers {len(new)} tool(s) not present at baseline: {', '.join(new)}"))
            if gone:
                findings.append(("server", f"server no longer offers: {', '.join(gone)}"))
            for name in sorted(set(offered) & set(baseline)):
                b, o = baseline[name], offered[name]
                if b.get("readOnlyHint") and not o.get("readOnlyHint"):
                    findings.append(("server", f"tool '{name}' was read-only at baseline and is not any more"))
                elif b != o:
                    findings.append(("server", f"tool '{name}' annotations changed: {b} -> {o}"))
    return calls, findings


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--server", help="only check events for this server label")
    parser.add_argument("traces", nargs="+")
    args = parser.parse_args()

    with open(args.policy) as fh:
        policy = json.load(fh)
    events = list(load_events(args.traces))
    server = args.server
    if server is None:
        labels = sorted({e.get("server") for e in events if e.get("event") == "call"})
        if len(labels) == 1:
            server = labels[0]
    calls, findings = check(policy, events, server)

    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    print(f"policy: {policy.get('name')}  calls checked: {len(calls)}  server: {server or 'all'}")
    if not findings:
        print("no drift: every call stayed inside the derived policy and the server offers the same tools")
        return 0
    print(f"DRIFT: {len(findings)} finding(s)")
    for kind, text in findings:
        print(f"  [{kind} drift] {text}")
        if gha:
            print(f"::error title=privilege drift ({kind})::{text}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
