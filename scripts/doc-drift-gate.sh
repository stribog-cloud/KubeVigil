#!/usr/bin/env bash
# Public surface drift gate (Developer Documentation Standard §4).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MAP="docs/dev/public-surface.md"
fail() { echo "doc-drift-gate: $*" >&2; exit 1; }

[[ -f "$MAP" ]] || fail "$MAP missing"

# MCP tools must match registered names in internal/mcp
for tool in kubevigil_scan kubevigil_get_findings kubevigil_get_summary; do
  grep -q "$tool" "$MAP" || fail "public-surface.md missing MCP tool $tool"
done

# CLI subcommands
for cmd in scan fix list version mcp-server; do
  grep -q "$cmd" "$MAP" || fail "public-surface.md missing CLI command $cmd"
done

# Checker count anchor
grep -q '110' "$MAP" || fail "public-surface.md missing checker count"

echo "doc-drift-gate: OK"