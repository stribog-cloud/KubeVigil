#!/usr/bin/env bash
# Compute statement coverage percent from coverage.out without go tool cover.
# go tool cover -func uses bufio.Scanner (64 KiB token limit) and flakes on long profile lines.
set -euo pipefail

profile="${1:-coverage.out}"
[[ -f "$profile" ]] || { echo "coverage-percent: missing profile: $profile" >&2; exit 1; }

awk '/^mode:/ {next} NF >= 3 { stmts += $2 + 0; if (($3 + 0) > 0) covered += $2 + 0 }
     END { if (stmts > 0) printf "%.1f", covered / stmts * 100; else print "0" }' "$profile"