# Changelog

All notable changes to KubeVigil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-02-20

### Added
- MCP server for AI assistant integration (Claude, Cursor, VS Code Copilot)
  - 6 tools: `scan_cluster`, `scan_manifests`, `get_findings`, `get_summary`, `list_checks`, `get_remediation`
  - stdio transport with JSON-RPC protocol
  - Input validation with path length limits and kubeconfig verification
  - Full test coverage: unit, integration, E2E (9 scenarios), benchmarks

### Fixed
- Fix engine path resolution: `runAsUser` field no longer corrupted when applying run-as-root fix
- CI coverage threshold raised from 90% to 94% to match project floor
- MCP SDK correctly marked as direct dependency (was indirect)
- gosec linter enabled for security-focused code scanning
- Contract test infrastructure moved from production code to test helpers (removes testify from binary)

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

[0.5.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/stribog-cloud/KubeVigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/stribog-cloud/KubeVigil/releases/tag/v0.1.0
