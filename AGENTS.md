# KubeVigil — Agent Onboarding

Read these documents **in order** before broad implementation work:

1. `docs/governance/Charter-Compliance-Annex.md` — charter pins, gates, paths
2. `docs/governance/MASTER-REFERENCE.md` — architecture source of truth
3. `docs/governance/testing-strategy.md` — TDD layers and coverage boundary
4. `docs/governance/WAIVER-REGISTER.md` — active exceptions (currently none)
5. `docs/dev/public-surface.md` — stable external contracts

## Non-negotiables

- **TDD:** failing test → implement → green → refactor (Engineering Charter §4.1)
- **Coverage:** 96% floor on `internal/` + `cmd/` (`make coverage`)
- **Gates:** `make all` must pass before claiming completion
- **Mutating safety:** `fix` is dry-run by default; never patch live clusters from agents
- **Attribution:** AI-assisted commits include `Co-authored-by:` trailer per Annex §3 (harness-specific: Claude `noreply@anthropic.com`, Grok `grok@x.ai`, etc.)
- **Public release profile:** do not reference `docs/internal/` from public docs

## Workflow

```bash
git checkout -b feat/<topic>
make all
# commit with conventional message
```

## Stable surfaces (do not break without ADR + migration)

- `checker.Checker` interface and `Finding` struct
- Golden scan → fix → re-scan workflow in `test/integration/`
- Eight report formats under `test/golden/`
- MCP tool names and JSON schemas in `internal/mcp/`

## Search

Use `code-graph.json` (regenerate with `make graph`) for package relationships.