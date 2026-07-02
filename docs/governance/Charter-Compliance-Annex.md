---
title: "KubeVigil Charter Compliance Annex"
created: 2026-07-02
updated: 2026-07-02
type: project/charter-compliance-annex
status: governing-reference
tags: [charter, governance, kubevigil, k8s, stribog]
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-02
owners: [stribog-team]
---

# KubeVigil — Charter Compliance Annex

> Authoritative declaration of charter pins, toolchain gates, documentation locations, and compliance posture for KubeVigil.

---

## 0. Charter Pins

| Governing Document | Applicability | Pinned Version | Pinned Revision (last reviewed at) |
|--------------------|---------------|----------------|------------------------------------|
| Universal Stribog Engineering Charter | Applies | 1.3 | revision 1, 2026-07-02 |
| Stribog Documentation Standard | Applies | 2.1 | revision 9, 2026-07-02 |
| Stribog AI Agent Execution Standard | Applies | 1.1 | revision 9, 2026-07-02 |
| Stribog Operational Delivery Standard | N/A — CLI tool, no managed-service scope | N/A | |
| Stribog Security Posture Standard | Applies — security tool, untrusted manifest input | 1.0 | revision 6, 2026-07-02 |
| Stribog Data and Privacy Standard | N/A — no PII collection or storage; scan input is cluster/manifest config | N/A | |
| Stribog User Documentation Standard | Applies — operator/integrator CLI and MCP | 1.0 | revision 2, 2026-07-02 |
| Stribog Developer Documentation Standard | Applies — public Go API, MCP surface, contributors | 1.0 | revision 2, 2026-07-02 |
| Stribog UI/UX Standard | N/A — line-oriented CLI per UI/UX §0.2 | N/A | |
| Stribog Glossary | Applies | 1.4 | revision 1, 2026-07-02 |
| Charter Governance | Applies | 1.4 | revision 1, 2026-07-02 |

| Property | Value |
|----------|-------|
| Project profile (Charter §0.4) | public library / package (CLI binary + MCP server) |
| Public release profile | See §X below |

## 0.1 Project Posture

| Property | Value |
|----------|-------|
| Project type | Go CLI + MCP server, public OSS, security-relevant |
| Compliance tier | Reference |
| Tier rationale | Public security tool; customer and operator trust requires full canon |
| Primary language(s) | Go 1.25+ |
| Delivery model | Tagged releases via GoReleaser |
| Public or private | public (Apache-2.0) |
| Operational scope | none |
| AI-assisted contribution | yes |
| Security Posture Standard binds | yes |
| Data and Privacy Standard binds | no |

## 1. Toolchain

### 1.1 Build, Test, and Quality Gates

| Gate (Charter §5.9) | Tool | Command |
|---------------------|------|---------|
| Format | gofmt + goimports | `make format` |
| Lint | golangci-lint | `make lint` |
| Static analysis | go vet | `make vet` |
| Test | go test -race | `make test` |
| Coverage | go test -coverprofile | `make coverage` |
| Secrets scan | gitleaks | `make secrets` |
| Vulnerability scan | govulncheck | `make vuln` |
| Build | go build | `make build` |
| All-up | combined | `make all` |

### 1.2 Repository Command Surface

Entrypoint: `Makefile`

Exposes: `format`, `lint`, `vet`, `test`, `coverage`, `secrets`, `vuln`, `build`, `all`, `hooks-install`, `doc-gate`, `doc-drift-gate`, `doc-samples-test`, `doc-a11y`

### 1.3 Coverage Boundary

| Property | Value |
|----------|-------|
| Coverage floor (Charter §5.4) | 96% |
| Project-declared floor | 96% |
| Per-package floor for critical paths | 98% for `internal/fix/`, `internal/mcp/`, `internal/checker/secrets/` |
| Measurement boundary | `internal/` and `cmd/` production packages |
| Excluded paths | `test/` (fixtures and harnesses), generated artifacts (none currently) |

### 1.4 Test Layers

| Layer | Tool / Pattern | Notes |
|-------|----------------|-------|
| Unit | table-driven Go tests | Per checker, reporter, fix component |
| Contract | `test/integration/contract_test.go` | All registered checkers |
| Golden | `test/golden/` | Stable report output |
| Integration | `test/integration/` | Scan/fix pipelines |
| End-to-end | Bats + optional Kind | `test/e2e/` |
| Benchmark | `go test -bench` | Hot paths in checker and report |

### 1.5 Local Hooks

| Hook | Implementation | Bootstrap |
|------|----------------|-----------|
| Pre-commit secrets scan | `.githooks/pre-commit` (gitleaks) | `make hooks-install` |

## 2. Documentation

### 2.1 Document Locations

| Document | Path |
|----------|------|
| Master reference | `docs/governance/MASTER-REFERENCE.md` |
| Threat model | `docs/governance/threat-model.md` |
| Build plan | `docs/governance/BUILD-PLAN.md` |
| ADRs | `docs/governance/adr/` |
| Audit closeouts | `docs/governance/audits/` |
| Testing strategy | `docs/governance/testing-strategy.md` |
| Local agent rules | `AGENTS.md` |
| Waiver register | `docs/governance/WAIVER-REGISTER.md` |
| Charter Compliance Annex | `docs/governance/Charter-Compliance-Annex.md` |

Internal engineering specs (`docs/internal/`) are **excluded** from the public release profile. Public governing documents must not depend on paths under `docs/internal/`.

### 2.2 Diagram Source

| Property | Value |
|----------|-------|
| Diagram language | D2 |
| D2 source path | `docs/governance/diagrams/src/` |
| Rendered output path | `docs/governance/diagrams/rendered/` |
| Rendered formats | SVG |

### 2.3 Public Trust Surface

| Surface | Status |
|---------|--------|
| README | maintained |
| Badges | CI, coverage, license, release — tied to automation |
| LICENSE | Apache-2.0 |
| SECURITY.md | private disclosure via GitHub Security tab |
| CODEOWNERS | `@msambare` |
| PR template | `.github/pull_request_template.md` |
| Issue templates | `.github/ISSUE_TEMPLATE/` |

### 2.4 User-Facing Documentation

| Property | Value |
|----------|-------|
| User-doc owner | maintainers (CODEOWNERS) |
| Active audience tiers | operator, integrator, evaluator |
| Quickstart | `docs/getting-started/quickstart.md` |
| How-to library | `docs/scanning/`, `docs/auto-fix/`, `docs/configuration/` |
| User reference | `docs/reference/` |
| Explanations | `docs/getting-started/concepts.md`, `docs/compliance/` |
| Troubleshooting + FAQ | `docs/troubleshooting/common-issues.md` |
| User-facing release notes | `docs/user/releases/` |
| Support escalation map | `docs/user/support.md` |
| Doc-to-release sync gate | `make doc-gate` |
| Doc accessibility command | `make doc-a11y` |

### 2.5 Developer-Facing Documentation

| Property | Value |
|----------|-------|
| Developer-doc owner | maintainers |
| Active audience tiers | contributor, consumer, embedder |
| README | `README.md` |
| CONTRIBUTING | `CONTRIBUTING.md` |
| Dev-env bootstrap | `docs/dev/bootstrap.md` |
| Onboarding budget | ≤ 6 commands to green smoke check |
| Architecture for contributors | `docs/dev/architecture.md` |
| ADR index | `docs/governance/adr/README.md` |
| Public surface map | `docs/dev/public-surface.md` |
| Deprecation register | `docs/dev/deprecations.md` |
| Compatibility window | one minor version |
| API reference | godoc / pkg.go.dev |
| Sample-test runner | `make doc-samples-test` |
| Drift-gate command | `make doc-drift-gate` |
| Reference hosting | pkg.go.dev + repository `docs/` |

## 3. Git, History, and Attribution

| Property | Value |
|----------|-------|
| Primary branch | `main` |
| Branch model | trunk-based, feature branches, squash merge |
| Required CI checks | lint, test (96% coverage), build, vulncheck, secrets-scan |
| Conventional Commits | yes — feat, fix, docs, chore, ci, test, perf |
| Git identity | `25719166+msambare@users.noreply.github.com` |
| AI attribution | `Co-authored-by: <AgentName> <noreply-address>` per AI Agent Execution Standard §5.1 |

## 4. AI Agent Posture

| Property | Value |
|----------|-------|
| AI-assisted contribution | yes |
| Permitted harnesses | Claude Code, Cursor, Codex, Grok, OpenCode |
| Closeout evidence | commit message body, PR description |
| Required reading order | This Annex → `AGENTS.md` → `docs/governance/MASTER-REFERENCE.md` → area-specific docs |

## 5. Operational Posture

Not applicable — CLI-only product.

## 6. Migration and Sunset

| Date | From | To | Notes |
|------|------|----|-------|
| 2026-07-02 | (none) | Charter set v1.3/v1.4 pins | Initial charter compliance program |

Migration cadence: review pins at each charter MAJOR bump; migrate within one quarter.

No planned sunset.

## 7. Active Waivers

No active waivers as of revision 1.

## 8. Annex Review Cadence

Reviewed at charter MAJOR bumps, phase boundaries, quarterly minimum, and toolchain changes.

---

## §X. Public Release Profile

**Applies:** yes — public derived projection at `https://github.com/stribog-cloud/KubeVigil`

### Included set

- All source under `cmd/`, `internal/`, `test/` (fixtures and tests)
- `docs/` except paths listed in excluded set
- `docs/governance/` (compliance and reference artifacts)
- Root governance: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `CHANGELOG.md`, `AGENTS.md`
- `.github/` workflows and templates
- `deploy/`, `install.sh`, `Makefile`, quality-gate config files

### Excluded set

- `docs/internal/` — internal specs, strategies, and prompts (operator-local BrainForest projection)
- `CLAUDE.md`, `CLAUDE-Phase*.md`, `.claude/`, `.goosehints` — local agent overrides
- `.beads/` — local issue tracker state
- `code-graph.json` — regenerable analysis artifact
- `scan-results/` — may contain cluster-sensitive output
- Build artifacts: `bin/`, `coverage.out`, `*.out`

### Cross-reference compliance attestation

- [x] No included artifact references an excluded artifact (Charter Governance §3.6, rule 1).
- [x] All gates bind to the included set (Charter Governance §3.6, rule 2).