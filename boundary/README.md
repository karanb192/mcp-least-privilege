# boundary: policy proxy for stdio MCP servers

`boundary.py` is a transparent JSON-RPC proxy. The client (Claude Code, Codex, a
script) starts boundary instead of the server; boundary starts the real server
and relays messages, enforcing a JSON policy on the way through. Standard
library only, Python 3.10 or newer, one file.

```
client  <--stdio-->  boundary.py --policy P.json -- <server command>  <--stdio-->  server
```

What it intercepts:

| message | what boundary does |
|---|---|
| `initialize` response | removes `resources` and `prompts` capabilities unless the policy enables them |
| `tools/list` response | drops tools the policy does not allow, so the model never sees them (`hide_denied_tools`, default true) |
| `tools/call` request | checks tool allowlist, per-argument rules, egress rules; denied calls are answered by boundary with `isError: true` and never reach the server |
| `resources/*`, `prompts/*` | answered with JSON-RPC `-32601 Method not found` when the capability is disabled |
| everything else | relayed unchanged |

Right after the client's `notifications/initialized`, boundary sends its own
`tools/list` to the server so it knows every tool's annotations even if the
client never lists (scripted clients often do not). That list is also written
to the trace, which is how the drift tooling sees the server's full offer.

## Running it

```
python3 boundary/boundary.py --policy policies/fs-docs-reader.json --root ./workspace \
    --name fs --trace traces/live/run.jsonl --taint-store .cache/taint.txt -- \
    npx -y @modelcontextprotocol/server-filesystem ./workspace
```

| flag | meaning |
|---|---|
| `--policy FILE` | the policy (below) |
| `--root DIR` | directory that `under` and `not_under` rules are relative to. Must match how the server resolves relative paths: the filesystem server resolves against its allowed directory, the git server against its cwd |
| `--name LABEL` | label written into every trace line (default: policy name) |
| `--trace FILE` | append one JSON line per decision; input for `tools/derive_policy.py` and `tools/drift_check.py` |
| `--taint-store FILE` | file of SHA-256 hashes shared between boundary processes, so data read through one server cannot leave through another |

In a Claude Code `.mcp.json`, the server entry's `command` is `python3` and
`args` is the line above split into words (see the repo's `.mcp.json`).

## Policy format

```json
{
  "name": "fs-docs-reader",
  "description": "free text",
  "default": "deny",
  "require_read_only_hint": true,
  "hide_denied_tools": true,
  "capabilities": {"resources": false, "prompts": false},
  "deny_tools": ["read_file"],
  "tools": {
    "read_text_file": {"args": {"path": {"under": ["docs"]}}},
    "search_files":   {"args": {"path": {"under": ["docs"]}, "pattern": {"max_len": 100}}},
    "fetch":          {"args": {"url": {"schemes": ["https"], "hosts": ["docs.python.org"], "max_query_len": 64}}}
  },
  "egress": {
    "outbound_tools": ["fetch"],
    "treat_open_world_as_outbound": true,
    "scan_secrets": true,
    "secret_patterns": ["AKIA[0-9A-Z]{16}"],
    "taint": true,
    "taint_min_len": 16
  },
  "deny_response": "tool_error"
}
```

| key | default | meaning |
|---|---|---|
| `default` | `deny` | `deny`: only tools listed under `tools` may be called or seen. `allow`: everything passes except `deny_tools` (the `unrestricted` baseline) |
| `tools` | `{}` | tool name (shell-style wildcards allowed) to its argument rules |
| `deny_tools` | `[]` | always refused, even with `default: allow` |
| `require_read_only_hint` | false | a listed tool is still refused unless the server annotates it `readOnlyHint: true`. Annotations are hints from the server, not proof; this is defence in depth, not the primary control |
| `hide_denied_tools` | true | filter `tools/list`. Set false to keep tools visible but refuse calls (useful to show the model a clear refusal) |
| `capabilities.resources`, `.prompts` | false | pass the server's resources or prompts capability through |
| `egress.outbound_tools` | `[]` | tools whose arguments are scanned before leaving |
| `egress.treat_open_world_as_outbound` | true | also scan any tool the server marks `openWorldHint: true` |
| `egress.scan_secrets` | true | refuse outbound arguments matching `secret_patterns` (defaults cover AWS keys, GitHub PATs, payment keys, webhook secrets, Slack tokens, PEM blocks, JWTs, `password=` style lines) |
| `egress.taint` | true | refuse outbound arguments containing any token this session read earlier (see below) |
| `deny_response` | `tool_error` | `tool_error` answers the call with `isError: true` text the model can read; `rpc_error` answers with a JSON-RPC error |

Argument rules (any combination, applied to string values; list-valued
arguments such as `paths` are checked element by element):

| rule | meaning |
|---|---|
| `under: [dirs]` | path, after `realpath` against `--root`, must be inside one of these (symlinks resolved, `..` normalised). `""` means anywhere under root |
| `not_under: [dirs]` | path must not be inside these |
| `hosts: [names]` | URL hostname must match exactly or by `*.suffix` |
| `schemes: [..]` | URL scheme allowlist (default `https` when any URL rule is present) |
| `max_query_len: n` | length of query plus fragment, so a URL cannot carry a long payload there (the path is not covered; the host allowlist is the first line) |
| `max_url_len: n` | default 2048 |
| `max_len: n` | maximum string length (for `content`, `query`, ...) |
| `enum: [..]` | value must be one of these |
| `allow_regex: [..]` | value must match one |
| `deny_regex: [..]` | value must match none |
| `required: true` | argument must be present |
| key `"*"` | rule applies to every string in the arguments, recursively |

### Taint: "cannot exfiltrate what it can read"

When a non-outbound tool returns text, boundary splits it into tokens (16 or
more characters containing a digit, and any `KEY=value` value of 8 or more)
and stores SHA-256 hashes of them. Before an outbound call, every string
argument (and its URL-decoded form) is tokenised the same way and each hash is
looked up. A hit refuses the call and names the token's first six characters.

With `--taint-store FILE` the hash set is a file, so the boundary in front of
the filesystem server learns and the boundary in front of the fetch server
checks. Only hashes are written; the file holds no secrets. The store is per
laptop and per session by convention: delete it between demos.

## What it does not stop

- An agent that encodes, splits or paraphrases data before sending it. Taint
  and secret scanning are exact-token checks. The host allowlist and query cap
  are the controls that hold regardless; treat scanning as a second net.
- Anything the server does on its own. boundary only sees the protocol; a
  server that phones home or follows symlinks internally is out of scope.
  Run servers in a sandbox too (MCP's own security guidance says the same).
- Resource and prompt content when you enable those capabilities. Only
  `tools/call` arguments are inspected.
- A client that connects to the server directly. boundary is only a boundary
  when it is the only path; project `.mcp.json` plus `--strict-mcp-config`
  gets you there in Claude Code.
- Trusting annotations. `require_read_only_hint` makes a server's own
  `readOnlyHint` a precondition, which is useful against a tool that quietly
  gains write behaviour, but a malicious server can lie. The allowlist is the
  control; the hint is a tripwire.
