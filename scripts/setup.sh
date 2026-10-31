#!/usr/bin/env bash
# One-command setup: checks the toolchain, pre-fetches the three reference
# servers so the first demo does not wait on a download, and drops the GitHub
# MCP server binary into .cache/bin (no global install, nothing outside the repo).
set -euo pipefail
cd "$(dirname "$0")/.."

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1 ($2)"; exit 1; }; }
need python3 "3.10 or newer, https://www.python.org"
need node    "24 or newer, https://nodejs.org (the filesystem server needs 24+)"
need npx     "comes with node"
need uvx     "https://docs.astral.sh/uv/ (uv ships uvx)"
need curl    "for the GitHub server download"
need tar     "for the GitHub server download"

python3 - <<'PY'
import sys
assert sys.version_info >= (3, 10), f"python 3.10+ needed, found {sys.version.split()[0]}"
print(f"python {sys.version.split()[0]} ok")
PY
node -e 'const [maj]=process.versions.node.split("."); if (+maj<24){console.error("node 24+ needed, found", process.versions.node); process.exit(1)}; console.log("node", process.versions.node, "ok")'
echo "uv $(uvx --version | awk '{print $2}') ok"

mkdir -p .cache/bin traces/live
echo
echo "pre-fetching reference servers (first run downloads, later runs hit the cache)..."
python3 tools/mcp_probe.py list -- npx -y @modelcontextprotocol/server-filesystem ./workspace 2>/dev/null | head -1
python3 tools/mcp_probe.py list -- uvx mcp-server-git --repository . 2>/dev/null | head -1
python3 tools/mcp_probe.py list -- uvx mcp-server-fetch 2>/dev/null | head -1

GH_VERSION="${GH_MCP_VERSION:-v2.0.3}"
if [[ ! -x .cache/bin/github-mcp-server ]]; then
  os=$(uname -s); arch=$(uname -m)
  case "$os-$arch" in
    Darwin-arm64)  asset="github-mcp-server_Darwin_arm64.tar.gz" ;;
    Darwin-x86_64) asset="github-mcp-server_Darwin_x86_64.tar.gz" ;;
    Linux-x86_64)  asset="github-mcp-server_Linux_x86_64.tar.gz" ;;
    Linux-aarch64|Linux-arm64) asset="github-mcp-server_Linux_arm64.tar.gz" ;;
    *) echo "no prebuilt github-mcp-server for $os-$arch; use docker (see README) or build from source"; asset="" ;;
  esac
  if [[ -n "$asset" ]]; then
    url="https://github.com/github/github-mcp-server/releases/download/${GH_VERSION}/${asset}"
    echo "downloading github-mcp-server ${GH_VERSION} ($asset)..."
    curl -sSL -o .cache/ghmcp.tar.gz "$url"
    tar -xzf .cache/ghmcp.tar.gz -C .cache/bin github-mcp-server
    rm -f .cache/ghmcp.tar.gz
    chmod +x .cache/bin/github-mcp-server
  fi
fi
if [[ -x .cache/bin/github-mcp-server ]]; then
  echo "github-mcp-server $(.cache/bin/github-mcp-server --version 2>/dev/null | head -1) ok (.cache/bin, token optional for tools/list)"
fi

echo
echo "setup complete. Try:  tests/smoke.sh        (deterministic checks of every control)"
echo "                      ./demo.sh inventory   (the privilege surface of the four servers)"
echo "                      ./demo.sh 2 replay    (deny-by-default at the boundary, no LLM needed)"
