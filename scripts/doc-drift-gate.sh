#!/usr/bin/env bash
# Public surface drift gate (Developer Documentation Standard §4).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MAP="docs/dev/public-surface.md"
MCP_SRC="internal/mcp/server.go"
CLI_DIR="cmd/kubevigil"
fail() { echo "doc-drift-gate: $*" >&2; exit 1; }

[[ -f "$MAP" ]] || fail "$MAP missing"
[[ -f "$MCP_SRC" ]] || fail "$MCP_SRC missing"

# MCP tools from ToolNames in internal/mcp/server.go
mcp_from_src=$(sed -n '/var ToolNames = \[\]string{/,/^}/p' "$MCP_SRC" \
  | sed -n 's/.*"\([^"]*\)".*/\1/p' | sort)
[[ -n "$mcp_from_src" ]] || fail "no MCP tools found in $MCP_SRC"

# CLI top-level commands registered on rootCmd in cmd/kubevigil/
cli_from_src=$(
  for f in "$CLI_DIR"/*.go; do
    grep -q 'rootCmd.AddCommand' "$f" || continue
    sed -n '/&cobra.Command{/,/}/p' "$f" \
      | sed -n 's/^[[:space:]]*Use:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -1 \
      | sed 's/ .*//'
  done | sort -u
)
[[ -n "$cli_from_src" ]] || fail "no CLI commands found in $CLI_DIR"

# Documented MCP tools and CLI commands from public-surface.md tables
mcp_from_doc=$(sed -n '/^## MCP tools/,/^## /p' "$MAP" \
  | grep '^|' | grep -v '^| Tool' | grep -v '^|---' \
  | sed 's/^| `\([^`]*\)`.*/\1/' | sort)

cli_from_doc=$(sed -n '/^## CLI commands/,/^## /p' "$MAP" \
  | grep '^|' | grep -v '^| Command' | grep -v '^|---' \
  | sed 's/^| `\([^`]*\)`.*/\1/' | sort)

# Checker count from MustRegister calls in internal/checker/*/register.go
checker_count=$(grep -h 'MustRegister' internal/checker/*/register.go 2>/dev/null | wc -l | tr -d ' ')
[[ "$checker_count" -gt 0 ]] || fail "no checkers found in internal/checker"
grep -qE "\\*\\*${checker_count}\\*\\*" "$MAP" || fail "public-surface.md missing checker count **${checker_count}**"

diff_sets() {
  local label=$1 src=$2 doc=$3
  local missing_from_doc missing_from_src
  missing_from_doc=$(comm -23 <(echo "$src") <(echo "$doc") || true)
  missing_from_src=$(comm -13 <(echo "$src") <(echo "$doc") || true)
  if [[ -n "$missing_from_doc" ]]; then
    fail "$label in source but missing from public-surface.md: $(echo "$missing_from_doc" | tr '\n' ' ')"
  fi
  if [[ -n "$missing_from_src" ]]; then
    fail "$label in public-surface.md but not in source: $(echo "$missing_from_src" | tr '\n' ' ')"
  fi
}

diff_sets "MCP tool" "$mcp_from_src" "$mcp_from_doc"
diff_sets "CLI command" "$cli_from_src" "$cli_from_doc"

echo "doc-drift-gate: OK"