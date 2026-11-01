#!/usr/bin/env python3
"""boundary: a deny-by-default policy proxy for stdio MCP servers.

Sits between an MCP client (Claude Code, Codex, a script) and a real MCP
server. The client talks to boundary; boundary talks to the server. Every
message passes through, except:

  * tools/list responses are filtered: tools the policy does not allow are
    removed, so the model never sees them.
  * tools/call requests are checked against the policy (tool allowlist,
    argument constraints, egress rules). Denied calls never reach the server;
    the client gets a tool error that names the policy.
  * initialize responses drop capabilities the policy disables (resources,
    prompts), and calls to those families get "method not found".
  * every decision is appended to a JSONL trace, which the drift tooling
    turns into a derived policy and diffs against later runs.

Standard library only. Python 3.10 or newer.

Usage:
  boundary.py --policy POLICY.json [--trace TRACE.jsonl] [--root DIR]
              [--name LABEL] -- <server command and args>
"""
import argparse
import asyncio
import datetime as dt
import fnmatch
import json
import os
import re
import sys
import urllib.parse

DEFAULT_SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                      # AWS access key id
    r"ghp_[A-Za-z0-9]{36}",                   # GitHub classic PAT
    r"github_pat_[A-Za-z0-9_]{22,}",          # GitHub fine-grained PAT
    r"sk-[A-Za-z0-9_-]{20,}",                 # generic sk- API keys
    r"[sr]k_(?:test|live)_[A-Za-z0-9]{10,}",  # payment provider keys
    r"whsec_[A-Za-z0-9_]{16,}",               # webhook signing secrets
    r"xox[baprs]-[A-Za-z0-9-]{10,}",          # Slack tokens
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",    # PEM private keys
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # JWT
    r"(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S{8,}",  # KEY=value lines
]

# One JSON-RPC message per line; a tools/list from a big server is well over
# asyncio's 64 KiB default line limit.
LINE_LIMIT = 64 * 1024 * 1024

RESOURCE_METHODS = ("resources/list", "resources/read", "resources/templates/list", "resources/subscribe", "resources/unsubscribe")
PROMPT_METHODS = ("prompts/list", "prompts/get")

PATH_KEYS = {"path", "paths", "source", "destination", "repo_path", "file", "filepath", "directory", "dir"}


def log(msg):
    print(f"[boundary] {msg}", file=sys.stderr, flush=True)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class Policy:
    def __init__(self, data, root):
        self.raw = data
        self.name = data.get("name", "unnamed")
        self.default = data.get("default", "deny")
        if self.default not in ("deny", "allow"):
            raise ValueError("policy.default must be 'deny' or 'allow'")
        self.tools = data.get("tools", {}) or {}
        self.deny_tools = set(data.get("deny_tools", []) or [])
        self.hide_denied = data.get("hide_denied_tools", True)
        self.require_read_only_hint = data.get("require_read_only_hint", False)
        caps = data.get("capabilities", {}) or {}
        self.allow_resources = caps.get("resources", False)
        self.allow_prompts = caps.get("prompts", False)
        egress = data.get("egress", {}) or {}
        self.egress_tools = set(egress.get("outbound_tools", []) or [])
        self.egress_open_world = egress.get("treat_open_world_as_outbound", True)
        self.scan_secrets = egress.get("scan_secrets", True)
        self.secret_patterns = [re.compile(p) for p in egress.get("secret_patterns", DEFAULT_SECRET_PATTERNS)]
        self.taint_enabled = egress.get("taint", True)
        self.taint_min_len = int(egress.get("taint_min_len", 16))
        self.deny_response = data.get("deny_response", "tool_error")
        self.root = os.path.realpath(root)
        self.root_label = root
        self.annotations = {}   # tool name -> annotations dict, learned from tools/list

    # ----- tool-level decisions -------------------------------------------------

    def tool_allowed(self, name):
        if name in self.deny_tools:
            return False, f"tool '{name}' is explicitly denied"
        if self.default == "allow":
            return True, ""
        for pattern in self.tools:
            if fnmatch.fnmatchcase(name, pattern):
                break
        else:
            return False, f"tool '{name}' is not in policy '{self.name}' (deny by default)"
        if self.require_read_only_hint:
            ann = self.annotations.get(name)
            if not ann or not ann.get("readOnlyHint"):
                return False, f"tool '{name}' is not declared read-only by the server and the policy requires readOnlyHint"
        return True, ""

    def rules_for(self, name):
        merged = {}
        for pattern, spec in self.tools.items():
            if fnmatch.fnmatchcase(name, pattern):
                merged.update((spec or {}).get("args", {}) or {})
        return merged

    def is_outbound(self, name):
        if name in self.egress_tools:
            return True
        if self.egress_open_world:
            ann = self.annotations.get(name) or {}
            if ann.get("openWorldHint"):
                return True
        return False

    # ----- argument-level decisions --------------------------------------------

    def check_args(self, name, arguments):
        rules = self.rules_for(name)
        for key, rule in rules.items():
            if key == "*":
                for k, v in walk_strings(arguments):
                    ok, why = self.check_value(rule, v, k)
                    if not ok:
                        return False, why
                continue
            if key not in arguments:
                if rule.get("required"):
                    return False, f"argument '{key}' is required by policy"
                continue
            values = arguments[key] if isinstance(arguments[key], list) else [arguments[key]]
            for v in values:
                ok, why = self.check_value(rule, v, key)
                if not ok:
                    return False, why
        return True, ""

    def check_value(self, rule, value, key):
        if not isinstance(value, str):
            return True, ""
        if "max_len" in rule and len(value) > rule["max_len"]:
            return False, f"argument '{key}' is {len(value)} chars, policy max is {rule['max_len']}"
        if "enum" in rule and value not in rule["enum"]:
            return False, f"argument '{key}'='{value}' not in allowed values {rule['enum']}"
        for pat in rule.get("deny_regex", []) or []:
            if re.search(pat, value):
                return False, f"argument '{key}' matches denied pattern /{pat}/"
        if "allow_regex" in rule and not any(re.search(p, value) for p in rule["allow_regex"]):
            return False, f"argument '{key}'='{value}' matches none of the allowed patterns"
        if "under" in rule:
            rel = self.relpath(value)
            if rel is None or not under_any(rel, rule["under"]):
                return False, f"path '{value}' is outside the allowed directories {rule['under']} (relative to {self.root_label})"
        if "not_under" in rule:
            rel = self.relpath(value)
            if rel is not None and under_any(rel, rule["not_under"]):
                return False, f"path '{value}' is inside a denied directory ({rule['not_under']})"
        if "hosts" in rule or "schemes" in rule or "max_query_len" in rule:
            parsed = urllib.parse.urlsplit(value)
            host = (parsed.hostname or "").lower()
            if "hosts" in rule and not host_allowed(host, rule["hosts"]):
                return False, f"host '{host}' is not in the egress allowlist {rule['hosts']}"
            schemes = rule.get("schemes", ["https"])
            if parsed.scheme not in schemes:
                return False, f"url scheme '{parsed.scheme}' not in {schemes}"
            if "max_query_len" in rule and len(parsed.query) + len(parsed.fragment) > rule["max_query_len"]:
                return False, f"url carries {len(parsed.query) + len(parsed.fragment)} chars of query/fragment, policy max is {rule['max_query_len']}"
            if "max_len" not in rule and len(value) > rule.get("max_url_len", 2048):
                return False, "url longer than policy max_url_len"
        return True, ""

    def relpath(self, value):
        try:
            expanded = os.path.expanduser(value)
            full = os.path.realpath(os.path.join(self.root, expanded))
        except (ValueError, OSError):
            return None
        if full == self.root:
            return ""
        if not full.startswith(self.root + os.sep):
            return None
        return os.path.relpath(full, self.root).replace(os.sep, "/")


def under_any(rel, dirs):
    """rel is a normalised path relative to root ('' for root itself)."""
    for d in dirs:
        d = d.strip("/")
        if d == "" or rel == d or rel.startswith(d + "/"):
            return True
    return False


def host_allowed(host, allowed):
    for pattern in allowed:
        pattern = pattern.lower()
        if pattern.startswith("*."):
            if host == pattern[2:] or host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def walk_strings(obj, prefix=""):
    if isinstance(obj, str):
        yield prefix or "value", obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{prefix}[{i}]")


class Taint:
    """Remembers secret-looking tokens the agent has read, so outbound calls
    carrying them can be refused.

    Only SHA-256 hashes of tokens are kept, never the tokens, so the store can
    be shared between the boundary processes guarding different servers (the
    filesystem proxy learns, the fetch proxy checks) without writing secrets
    to disk. Deterministic and in-session: a stranger's data is not involved.
    """

    SPLIT = re.compile(r"[\s\"'`,;:/@?&=<>()\[\]{}|\\]+")

    def __init__(self, min_len, store_path=None):
        self.min_len = min_len
        self.store_path = store_path
        self.hashes = set()
        self._load()

    def _load(self):
        if self.store_path and os.path.exists(self.store_path):
            with open(self.store_path) as fh:
                self.hashes.update(line.strip() for line in fh if line.strip())

    @staticmethod
    def _digest(tok):
        import hashlib
        return hashlib.sha256(tok.encode("utf-8", "replace")).hexdigest()

    def _tokens(self, text):
        seen = set()
        for tok in self.SPLIT.split(text):
            tok = tok.strip()
            if len(tok) >= self.min_len and re.search(r"\d", tok):
                seen.add(tok)
        for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*([^\s\"']{8,})", text):
            seen.add(m.group(1))
        return seen

    def learn(self, text):
        new = {self._digest(t) for t in self._tokens(text)} - self.hashes
        if not new:
            return
        self.hashes.update(new)
        if self.store_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.store_path)), exist_ok=True)
            with open(self.store_path, "a") as fh:
                fh.write("".join(h + "\n" for h in sorted(new)))

    def hit(self, text):
        self._load()
        if not self.hashes:
            return None
        candidates = [text]
        try:
            candidates.append(urllib.parse.unquote_plus(text))
        except Exception:
            pass
        for c in candidates:
            for tok in self._tokens(c):
                if self._digest(tok) in self.hashes:
                    return tok
        return None


class Boundary:
    def __init__(self, policy, trace_path, label, taint_store=None):
        self.policy = policy
        self.label = label
        self.trace_path = trace_path
        self.taint = Taint(policy.taint_min_len, taint_store)
        self.pending = {}  # request id -> ("init"|"list"|"call"|"internal_list", payload)
        self.client_out = None
        self.server_in = None
        self.counts = {"allow": 0, "deny": 0}
        self.tools_learned = asyncio.Event()
        self._internal_seq = 0

    # ----- trace -----------------------------------------------------------------

    def trace(self, event):
        event = {"ts": now(), "server": self.label, **event}
        if self.trace_path:
            with open(self.trace_path, "a") as fh:
                fh.write(json.dumps(event, sort_keys=True) + "\n")

    @staticmethod
    def summarize_args(arguments, policy):
        paths, hosts, keys = [], [], []
        for key, value in walk_strings(arguments):
            keys.append(key)
            base = key.split(".")[-1].split("[")[0]
            if value.startswith(("http://", "https://")):
                h = urllib.parse.urlsplit(value).hostname
                if h:
                    hosts.append(h.lower())
            elif base in PATH_KEYS:
                rel = policy.relpath(value)
                paths.append(rel if rel is not None else f"OUTSIDE_ROOT:{value}")
        return {"paths": sorted(set(paths)), "hosts": sorted(set(hosts)), "arg_keys": sorted(set(keys))}

    # ----- client -> server -------------------------------------------------------

    async def handle_client_message(self, msg):
        method = msg.get("method")
        rid = msg.get("id")
        if method == "initialize" and rid is not None:
            self.pending[rid] = ("init", None)
        elif method == "tools/list" and rid is not None:
            self.pending[rid] = ("list", None)
        elif method == "tools/call" and rid is not None:
            await self.handle_tool_call(msg)
            return
        elif method == "notifications/initialized":
            await self.send_server(msg)
            await self.learn_tools()
            return
        elif method in RESOURCE_METHODS and not self.policy.allow_resources:
            self.trace({"event": "method", "method": method, "decision": "deny", "reason": "resources capability disabled by policy"})
            await self.reply_error(rid, -32601, f"Method not found: {method} (resources disabled by policy '{self.policy.name}')")
            return
        elif method in PROMPT_METHODS and not self.policy.allow_prompts:
            self.trace({"event": "method", "method": method, "decision": "deny", "reason": "prompts capability disabled by policy"})
            await self.reply_error(rid, -32601, f"Method not found: {method} (prompts disabled by policy '{self.policy.name}')")
            return
        await self.send_server(msg)

    async def learn_tools(self):
        """Ask the server for its tool list ourselves, so annotation-based rules
        work even for a client that calls a tool without listing first."""
        self._internal_seq += 1
        rid = f"boundary-internal-{self._internal_seq}"
        self.pending[rid] = ("internal_list", None)
        await self.send_server({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})

    async def handle_tool_call(self, msg):
        rid = msg["id"]
        if not self.tools_learned.is_set():
            try:
                await asyncio.wait_for(self.tools_learned.wait(), timeout=15)
            except asyncio.TimeoutError:
                log("server did not answer tools/list; annotation-based rules will deny")
        params = msg.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        summary = self.summarize_args(arguments, self.policy)
        event = {"event": "call", "tool": name, **summary, "annotations": self.policy.annotations.get(name)}

        ok, reason = self.policy.tool_allowed(name)
        if ok:
            ok, reason = self.policy.check_args(name, arguments)
        if ok and self.policy.is_outbound(name):
            ok, reason = self.check_egress(name, arguments)
        if not ok:
            self.counts["deny"] += 1
            self.trace({**event, "decision": "deny", "reason": reason})
            log(f"DENY {name} {json.dumps(summary['paths'] or summary['hosts'])}: {reason}")
            await self.reply_denied(rid, name, reason)
            return
        self.counts["allow"] += 1
        self.pending[rid] = ("call", {**event, "decision": "allow"})
        await self.send_server(msg)

    def check_egress(self, name, arguments):
        for key, value in walk_strings(arguments):
            if self.policy.scan_secrets:
                for pat in self.policy.secret_patterns:
                    if pat.search(value) or pat.search(urllib.parse.unquote(value)):
                        return False, f"outbound argument '{key}' contains a secret-shaped token (/{pat.pattern}/)"
            if self.policy.taint_enabled:
                tok = self.taint.hit(value)
                if tok:
                    return False, f"outbound argument '{key}' contains data this session read earlier ({tok[:6]}... redacted)"
        return True, ""

    async def reply_denied(self, rid, name, reason):
        if self.policy.deny_response == "rpc_error":
            await self.reply_error(rid, -32000, f"boundary denied {name}: {reason}")
            return
        text = f"boundary denied '{name}': {reason}. Policy: {self.policy.name}."
        await self.send_client({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}], "isError": True}})

    async def reply_error(self, rid, code, message):
        if rid is None:
            return
        await self.send_client({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})

    # ----- server -> client -------------------------------------------------------

    async def handle_server_message(self, msg):
        rid = msg.get("id")
        if rid is not None and rid in self.pending and "method" not in msg:
            kind, payload = self.pending.pop(rid)
            if kind == "init":
                self.filter_init(msg)
            elif kind == "list":
                self.filter_list(msg)
            elif kind == "call":
                self.record_result(payload, msg)
            elif kind == "internal_list":
                self.filter_list(msg, forwarded=False)
                return
        await self.send_client(msg)

    def filter_init(self, msg):
        result = msg.get("result") or {}
        caps = result.get("capabilities") or {}
        dropped = []
        if not self.policy.allow_resources and "resources" in caps:
            caps.pop("resources")
            dropped.append("resources")
        if not self.policy.allow_prompts and "prompts" in caps:
            caps.pop("prompts")
            dropped.append("prompts")
        if dropped:
            log(f"initialize: dropped capabilities {dropped}")
        self.trace({"event": "initialize", "server_info": result.get("serverInfo"), "capabilities_dropped": dropped})

    def filter_list(self, msg, forwarded=True):
        result = msg.get("result") or {}
        tools = result.get("tools") or []
        for t in tools:
            self.policy.annotations[t["name"]] = t.get("annotations") or {}
        self.tools_learned.set()
        exposed, hidden = [], []
        for t in tools:
            ok, _ = self.policy.tool_allowed(t["name"])
            (exposed if ok else hidden).append(t)
        if self.policy.hide_denied and forwarded:
            result["tools"] = exposed
        log(f"tools/list: server offered {len(tools)}, policy '{self.policy.name}' exposes {len(exposed)}, hidden {len(hidden)}")
        self.trace({
            "event": "tools_list",
            "requested_by": "client" if forwarded else "boundary",
            "offered": [{"name": t["name"], "annotations": t.get("annotations") or {}} for t in tools],
            "exposed": [t["name"] for t in exposed],
            "hidden": [t["name"] for t in hidden],
        })

    def record_result(self, event, msg):
        result = msg.get("result") or {}
        text = "".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
        if "error" in msg:
            event["result"] = {"is_error": True, "bytes": len(json.dumps(msg["error"]))}
        else:
            event["result"] = {"is_error": bool(result.get("isError")), "bytes": len(text)}
            if self.policy.taint_enabled and text and not self.policy.is_outbound(event["tool"]):
                self.taint.learn(text)
        self.trace(event)

    # ----- plumbing ------------------------------------------------------------------

    async def send_client(self, msg):
        self.client_out.write((json.dumps(msg) + "\n").encode())
        await self.client_out.drain()

    async def send_server(self, msg):
        self.server_in.write((json.dumps(msg) + "\n").encode())
        await self.server_in.drain()


async def pump(reader, handler, on_eof, side):
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log(f"dropping non-JSON line from {side}: {line[:80]!r}")
                continue
            await handler(msg)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # keep the other direction alive long enough to report
        log(f"{side} pump failed: {exc!r}")
    on_eof()


async def run(policy, trace_path, label, command, taint_store=None):
    boundary = Boundary(policy, trace_path, label, taint_store)
    proc = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, limit=LINE_LIMIT)
    boundary.server_in = proc.stdin

    loop = asyncio.get_running_loop()
    client_reader = asyncio.StreamReader(limit=LINE_LIMIT)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(client_reader), sys.stdin)
    transport, protocol = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, os.fdopen(sys.stdout.fileno(), "wb", 0))
    boundary.client_out = asyncio.StreamWriter(transport, protocol, None, loop)

    done = asyncio.Event()

    def client_closed():
        try:
            proc.stdin.close()
        except Exception:
            pass
        done.set()

    def server_closed():
        done.set()

    log(f"policy '{policy.name}' (default {policy.default}) guarding: {' '.join(command)}")
    t1 = asyncio.create_task(pump(client_reader, boundary.handle_client_message, client_closed, "client"))
    t2 = asyncio.create_task(pump(proc.stdout, boundary.handle_server_message, server_closed, "server"))
    await done.wait()
    for t in (t1, t2):
        t.cancel()
    try:
        await asyncio.wait_for(proc.wait(), timeout=3)
    except asyncio.TimeoutError:
        proc.kill()
    log(f"session over: {boundary.counts['allow']} calls allowed, {boundary.counts['deny']} denied")
    return proc.returncode or 0


def main():
    argv = sys.argv[1:]
    if "--" not in argv:
        sys.exit("usage: boundary.py --policy POLICY.json [--trace FILE] [--root DIR] [--name LABEL] -- <server command>")
    idx = argv.index("--")
    own, command = argv[:idx], argv[idx + 1 :]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", required=True, help="policy JSON file")
    parser.add_argument("--trace", help="append JSONL decisions here")
    parser.add_argument("--root", default=".", help="directory that 'under' path rules are relative to (default: cwd)")
    parser.add_argument("--name", help="label for this server in traces (default: policy name)")
    parser.add_argument("--taint-store", help="file of hashed tokens shared between boundary processes, so what one server read cannot leave through another")
    args = parser.parse_args(own)
    if not command:
        sys.exit("no server command given after '--'")
    with open(args.policy) as fh:
        policy = Policy(json.load(fh), args.root)
    if args.trace:
        os.makedirs(os.path.dirname(os.path.abspath(args.trace)), exist_ok=True)
    code = asyncio.run(run(policy, args.trace, args.name or policy.name, command, args.taint_store))
    sys.exit(code)


if __name__ == "__main__":
    main()
