# Changelog

All notable changes to KubeVigil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-06

First stable release. The public surface — CLI commands and flags, exit codes,
the 8 output formats, the configuration schema, and the 6 MCP tools — is now
covered by semantic-versioning stability guarantees (`docs/dev/public-surface.md`,
`docs/dev/deprecations.md`).

### Added

- **Supply-chain release integrity**: SPDX SBOM per release archive (syft);
  keyless Cosign signature over the checksums file (Sigstore); SLSA build
  provenance attestations; multi-arch (amd64/arm64) distroless container
  images published to `ghcr.io/stribog-cloud/kubevigil`
- **First-party GitHub Action** (`action.yml`) for manifest scanning in CI:
  downloads and checksum-verifies a release binary, scans, and writes a report
  (SARIF by default); see `docs/integrations/github-action.md`
- **E2E suite in CI**: the 93-test kind + Bats end-to-end suite runs nightly
  and on demand (`workflow_dispatch`)
- **Cross-compile gate**: CI builds all 5 release targets and vets
  platform-tagged code (`GOOS=windows`/`darwin`) on every PR
- `scripts/update-krew-manifest.sh` regenerates the krew manifest from release
  checksums instead of hand-maintained values
- Stribog Charter compliance program: Charter Compliance Annex, master reference, testing strategy, threat model, ADRs, waiver register, and public release profile (`docs/governance/`)
- `AGENTS.md` and root `CONTRIBUTING.md` for agent and contributor onboarding
- Documentation gates: `make doc-gate`, `make doc-drift-gate`, `make doc-samples-test`, `make doc-a11y`
- User support escalation map (`docs/user/support.md`) and user-facing release notes index

### Fixed

- **Windows build restored**: the MCP workspace-jail path walk
  (`internal/pathguard`) did not compile on `windows/amd64` since its
  introduction; Windows now has a dedicated best-effort confined-open
  implementation (component-wise `Lstat` walk with `SameFile` re-verification)
- Stale compliance control counts in `docs/compliance/overview.md`
  (CIS 35, MITRE ATT&CK 29, NSA/CISA 15)
- `kubevigil mcp-server` documented in the CLI reference; four orphaned user
  docs linked from the docs index

### Changed

- CI and Makefile enforce **96%** coverage floor on `internal/` + `cmd/` (Stribog Engineering Charter §5.4); supersedes the prior **94%** project floor documented in v0.5.0 release notes
- Release workflow actions pinned to commit SHAs; gitleaks pinned (8.30.1,
  checksum-verified); GoReleaser pinned to 2.16.0
- Homebrew tap publishing uses a dedicated token; prerelease tags never update
  the tap or move the `:latest` image
- Branch protection additionally requires the Documentation Gates and Secrets
  Scan checks
- Golden workflow wording clarified: scan → fix → re-scan yields zero
  *fixable* findings
- `//nolint:gosec` on manifest reads documents G304 justification (path confinement or operator trust), not security hardening by annotation alone
- Governing documentation standardized on **96%** floor across Annex, `AGENTS.md`, `CONTRIBUTING.md`, and `testing-strategy.md`
- `make all` is the canonical quality gate entrypoint; install script URLs use `main` branch
- Bumped `github.com/modelcontextprotocol/go-sdk` to v1.4.1 and `golang.org/x/net` to v0.55.0 (govulncheck clean)

### Security

- Declared artifact size budget: ≤ 50 MB per uncompressed binary, ≤ 20 MB per
  compressed archive (checked in release evidence)
- Threat model updated with the Windows pathguard guarantee tier
- Historic release tags (v0.3.0–v0.5.0) retargeted to the current repository
  lineage; stale draft releases removed

## [0.5.0] - 2026-02-20

### Security
- MCP path validation uses `os.Lstat` to detect and reject symlinks in manifest and kubeconfig paths
- Fix engine uses `os.Lstat` in Apply, planFile, and collectFiles to prevent writing through symlinks
- Backup path boundary enforcement: reject `filepath.Rel` results that escape the source directory
- YAML document count limit (10,000) in both engine and fix parsers prevents memory exhaustion
- Namespace (253 char) and context (512 char) length validation in MCP `scan_cluster`

### Fixed
- Fix engine path resolution: `runAsUser` field no longer corrupted when applying run-as-root fix
- CI coverage threshold raised from 90% to 94% to match project floor
- gosec linter enabled for security-focused code scanning
- Contract test infrastructure moved from production code to test helpers (removes testify from binary)
- Internal engineering documents removed from git tracking (will not ship in public repo)
- README and documentation checker counts corrected (Workload: 25, Supply Chain: 5)
- File size limits added to YAML parsing paths (manifest parser 10 MiB, config loader 1 MiB, fix engine 10 MiB)
- MCP manifest path validation now verifies file existence and rejects non-regular files
- Duplicate system namespace definitions consolidated into shared `internal/k8s` package
- MCP `checkerDefaultSeverity` replaced hardcoded "Medium" with per-checker severity map (110 entries)
- Bare error returns wrapped with context in scan.go and mcp.go
- Dead code removed from kubelet_config.go
- `lastResult` immutability invariant documented in MCP server
- Documentation accuracy fixes: config key `disabled`, exemption format `checks: []`, install URLs, CLI reference version
- `k8s.io/utils` moved from direct to indirect dependency
- Go pinned to 1.25.7 in go.mod and Dockerfile
- CI: `CGO_ENABLED=0` build, short SHA, strip ldflags, `make build` before tests
- Test coverage improved from 94.0% to 94.7%

## [0.4.5] - 2026-02-15

### Added
- MCP server for AI assistant integration (Claude, Cursor, VS Code Copilot)
  - 6 tools: `scan_cluster`, `scan_manifests`, `get_findings`, `get_summary`, `list_checks`, `get_remediation`
  - stdio transport with JSON-RPC protocol
  - Input validation with path length limits and kubeconfig verification
  - Full test coverage: unit, integration, E2E (9 scenarios), benchmarks
- MCP setup guide with configuration examples for Claude Desktop, Cursor, VS Code

### Fixed
- MCP SDK correctly marked as direct dependency (was indirect)
- MCP severity schema type mismatch corrected (string, not integer)
- `MCPFinding` renamed to `FindingDetail` to fix revive stutter lint
- Go pinned to 1.25.7 to resolve GO-2026-4337 govulncheck finding

## [0.4.0] - 2025-12-01

### Added
- Distribution pipeline: GoReleaser cross-compilation (linux/darwin/windows x amd64/arm64)
- GitHub Releases with binary archives and SHA256 checksums
- Docker image (distroless, nonroot, multi-stage build)
- Homebrew formula and Krew manifest
- Install script with checksum verification
- CI pipeline: lint, test, build, vulncheck with coverage badge
- Makefile with build/test/lint/vet/cover/vulncheck/clean targets

## [0.3.0] - 2025-10-01

### Added
- `kubevigil fix` command with 20 auto-fixable checks
- Comment-preserving YAML round-trip patching via `yaml.v3` Node API
- Five-ring safety model: dry-run default, risk-level gating, system namespace hard block, interactive confirmation, mandatory backup
- Three risk levels: safe (7 checks), likely safe (9 checks), potentially breaking (4 checks)
- Dry-run mode with unified diff preview (ANSI colored)
- Backup and restore with timestamped snapshots and `RESTORE.md`
- Known workload detection (CNI, storage drivers, exporters) to avoid breaking system components
- Fix verification via `--verify` (re-scan after patching)
- Structured exit codes (0=success, 1=verify remaining, 2=error, 3=config, 4=nothing to fix, 5=partial)
- Kustomize overlay generation (`--kustomize`)
- Helm `values.yaml` security defaults (`--output helm-values`)
- `kubectl patch` command generation (`--output kubectl`)
- Markdown fix report (`--report`)
- GitOps PR generation via `gh`/`glab` (`--git-pr`)

## [0.2.0] - 2025-08-01

### Added
- 85 additional security checks (110 total across 12 categories): RBAC (15), Network (12), Cluster (10), Image (9), Scheduling (8), Secrets (7), PSA (6), Storage (5), Supply Chain (5), Cloud (4), CRD (4)
- 6 new output formats: YAML, Markdown, HTML (interactive dashboard with dark mode, posture scoring, compliance tabs), SARIF, JUnit XML, CSV
- Compliance framework mapping: CIS Kubernetes Benchmark v1.8, MITRE ATT&CK v14, NSA/CISA Hardening Guide v1.2
- Framework-based filtering with `--framework`
- Executive summary with posture scoring (0-100, A/B/C/D/F grades), per-category and tier-based breakdown
- YAML configuration file (`.kubevigil.yaml`) with severity overrides, check enable/disable, per-resource exemptions
- Performance optimizations: `ExtractPodSpecs` caching (42% faster), `ResourceCache.List()` freeze (7.7x faster), single-pass `ComputeSummary`, flat-table LCS diff

## [0.1.0] - 2025-06-01

### Added
- Dual-mode scanning engine: live Kubernetes clusters (via kubeconfig) and static YAML manifests
- Concurrent check execution with configurable parallelism via `errgroup`
- 25 workload security checks: privileged containers, capabilities, run-as-root, read-only rootfs, resource limits/requests, host PID/IPC/network/ports/path, privilege escalation, seccomp/AppArmor/SELinux, proc mount, unsafe sysctls, and more
- Text and JSON output formats
- CLI commands: `kubevigil scan`, `kubevigil list checks`, `kubevigil version`
- Namespace filtering (`--namespace`, `--exclude-namespace`), system namespace classification
- Annotation-based per-resource exemptions (`kubevigil.io/skip`)
- `--fail-on` severity threshold for CI exit codes
- Shell completion for Bash, Zsh, Fish, and PowerShell
- Table-driven unit tests with 15+ cases per checker, contract tests for all checkers
- E2E test suite via Bats framework with Kind cluster validation

[1.0.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.4.5...v0.5.0
[0.4.5]: https://github.com/stribog-cloud/KubeVigil/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/stribog-cloud/KubeVigil/releases/tag/v0.1.0
