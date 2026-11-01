#!/usr/bin/env python3
"""Minimal MCP stdio client for demos and tests. Standard library only.

Speaks newline-delimited JSON-RPC to any stdio MCP server (or to the boundary
proxy in front of one), runs the initialize handshake, then lists tools and
optionally calls one. Nothing here depends on an LLM, so every run is
deterministic and shows exactly what a model would be allowed to do.

Usage:
  mcp_probe.py list [--json] -- <server command...>
  mcp_probe.py call <tool> '<json args>' -- <server command...>
  mcp_probe.py script <file.jsonl> -- <server command...>

`script` replays a sequence of tool calls from a JSONL file (one
{"tool": ..., "arguments": {...}} per line), which is how the demos replay an
injected instruction sequence without a model in the loop.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import queue

PROTOCOL_VERSION = "2025-06-18"


class StdioClient:
    def __init__(self, command, env=None, timeout=60):
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **(env or {})},
            text=True,
            bufsize=1,
        )
        self.timeout = timeout
        self._id = 0
        self._lines = queue.Queue()
        self._stderr = []
        threading.Thread(target=self._pump, args=(self.proc.stdout, self._lines), daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump(self, stream, q):
        for line in stream:
            q.put(line)
        q.put(None)

    def _pump_err(self):
        for line in self.proc.stderr:
            self._stderr.append(line)

    def stderr_text(self):
        return "".join(self._stderr)

    def _send(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None):
        self._id += 1
        rid = self._id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        while True:
            try:
                line = self._lines.get(timeout=self.timeout)
            except queue.Empty:
                raise TimeoutError(f"no response to {method} within {self.timeout}s; server stderr:\n{self.stderr_text()}")
            if line is None:
                raise RuntimeError(f"server exited before answering {method}; stderr:\n{self.stderr_text()}")
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue
            if resp.get("id") == rid:
                if "error" in resp:
                    raise RuntimeError(f"{method} failed: {json.dumps(resp['error'])}")
                return resp.get("result")
            # notifications and unrelated messages are ignored

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def initialize(self):
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-probe", "version": "0.1"},
            },
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self):
        return self.request("tools/list", {}).get("tools", [])

    def call_tool(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def summarize_annotations(tool):
    ann = tool.get("annotations") or {}
    flags = []
    if ann.get("readOnlyHint"):
        flags.append("read-only")
    else:
        flags.append("WRITE")
    if ann.get("destructiveHint", True) and not ann.get("readOnlyHint"):
        flags.append("destructive")
    if ann.get("openWorldHint", True):
        flags.append("open-world")
    if not ann:
        return "no annotations (assume write, destructive, open-world)"
    return ", ".join(flags)


def render_result(result):
    if result is None:
        return ""
    parts = []
    for item in result.get("content", []):
        if item.get("type") == "text":
            parts.append(item.get("text", ""))
        else:
            parts.append(f"<{item.get('type')} content>")
    text = "\n".join(parts)
    if result.get("isError"):
        return f"[tool error] {text}"
    return text


def split_command(argv):
    if "--" not in argv:
        sys.exit("expected '--' followed by the server command")
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1 :]


def main():
    own, command = split_command(sys.argv[1:])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list")
    p_list.add_argument("--json", action="store_true", help="print raw tool definitions")
    p_call = sub.add_parser("call")
    p_call.add_argument("tool")
    p_call.add_argument("arguments", nargs="?", default="{}")
    p_script = sub.add_parser("script")
    p_script.add_argument("file")
    for p in (p_list, p_call, p_script):
        p.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(own)

    if not command:
        sys.exit("empty server command")

    client = StdioClient(command, timeout=args.timeout)
    try:
        info = client.initialize()
        server = info.get("serverInfo", {})
        print(f"# server: {server.get('name', '?')} {server.get('version', '')}  protocol {info.get('protocolVersion')}", file=sys.stderr)

        if args.cmd == "list":
            tools = client.list_tools()
            if args.json:
                print(json.dumps(tools, indent=2))
            else:
                print(f"{len(tools)} tools exposed")
                for t in sorted(tools, key=lambda t: t["name"]):
                    print(f"  {t['name']:<32} {summarize_annotations(t)}")
        elif args.cmd == "call":
            result = client.call_tool(args.tool, json.loads(args.arguments))
            print(render_result(result))
            if result and result.get("isError"):
                sys.exit(3)
        elif args.cmd == "script":
            failed = 0
            with open(args.file) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    step = json.loads(line)
                    label = step.get("note") or step["tool"]
                    print(f"\n>>> {step['tool']} {json.dumps(step.get('arguments', {}))}")
                    if step.get("note"):
                        print(f"    ({step['note']})")
                    try:
                        result = client.call_tool(step["tool"], step.get("arguments", {}))
                        out = render_result(result)
                        if result and result.get("isError"):
                            failed += 1
                        print("    " + out.replace("\n", "\n    ")[:1200])
                    except RuntimeError as exc:
                        failed += 1
                        print(f"    [rpc error] {exc}")
            print(f"\n{failed} call(s) refused or failed")
    finally:
        client.close()


if __name__ == "__main__":
    main()
