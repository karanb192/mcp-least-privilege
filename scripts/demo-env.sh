#!/usr/bin/env bash
# Start Claude Code for a recorded demo with a clean, repo-local profile:
# no personal instructions, plugins, status line or user hooks on screen.
# The profile lives in demo-profile/ (gitignored). First run asks you to log in.
#
#   scripts/demo-env.sh                      interactive, repo .mcp.json + hook
#   scripts/demo-env.sh mcp/demo2-scoped.json  interactive with one of the mcp/ configs
set -euo pipefail
cd "$(dirname "$0")/.."
export CLAUDE_CONFIG_DIR="$PWD/demo-profile"
mkdir -p "$CLAUDE_CONFIG_DIR"
for v in $(env | grep -E '^(CLAUDECODE|CLAUDE_CODE_)' | cut -d= -f1); do unset "$v"; done
if [[ $# -gt 0 ]]; then
  exec claude --strict-mcp-config --mcp-config "$1"
fi
exec claude
