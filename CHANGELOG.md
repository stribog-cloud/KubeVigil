# Changelog

All notable changes to KubeVigil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Scanning Engine
- Dual-mode scanning: live Kubernetes clusters (via kubeconfig) and static YAML manifests
- Concurrent check execution with configurable parallelism via `errgroup`
- ResourceCache with `Freeze()` optimization for zero-allocation `List()` calls
- Multi-document YAML parsing with directory recursion
- Namespace filtering (`--namespace`, `--exclude-namespace`) and resource exemptions
- Annotation-based per-resource exemptions (`kubevigil.io/skip`)
- System namespace classification and `--include-system-namespaces` flag
- Infrastructure workload filtering with `--exclude-infra`
- Finding aggregation by check with `--no-aggregate` to disable
- Summary-only output mode with `--summary-only`
- `--fail-on` severity threshold for CI exit codes

#### Security Checks (110 checks across 12 categories)
- **Workload** (25 checks): privileged containers, added/undropped capabilities, run-as-root, run-as-high-UID, run-as-group, read-only rootfs, resource limits/requests/ratio, ephemeral storage limits, host PID/IPC/network/ports/path volumes, privilege escalation, seccomp/AppArmor/SELinux profiles, proc mount, unsafe sysctls, runtime class, shared process namespace, ephemeral container policy
- **RBAC** (15 checks): default service account usage, automount token, token projection config, wildcard verbs/resources/API groups, escalation verbs, secret/exec/log access, cluster-admin binding, unused roles, group bindings, external subjects, cloud IAM bindings
- **Network** (12 checks): missing NetworkPolicy, no default deny, overly permissive policies, unrestricted egress, Ingress without TLS/with wildcard host/missing class, LoadBalancer/NodePort services, external IPs, service mesh mTLS, DNS security
- **Cluster** (10 checks): default namespace usage, missing LimitRange/ResourceQuota, API server anonymous auth, audit logging, admission controllers, etcd encryption, kubelet config, component versions, deprecated API usage
- **Image** (9 checks): latest tag, missing tag, no digest, pull policy, registry allowlist/blocklist, signature verification, SBOM attestation, provenance
- **Scheduling** (8 checks): control-plane tolerations, tolerate-all, system/missing PriorityClass, PodDisruptionBudget, topology spread, untrusted node affinity, HPA without requests
- **Secrets** (7 checks): secrets in env vars, unencrypted secrets, secrets in ConfigMaps, default Secret type, stale secrets, hardcoded credentials in manifests, external secrets sync
- **PSA** (6 checks): missing labels, audit-only mode, baseline violations, restricted violations, version pinning, deprecated PSP still present
- **Storage** (5 checks): PVC without encryption, PVC reclaim policy, CSI driver security, emptyDir without size limit, projected volume security
- **Supply Chain** (5 checks): container runtime socket mounts, missing liveness/readiness probes, missing startup probes, missing lifecycle hooks, image age
- **Cloud** (4 checks): EKS IMDS access, GKE metadata concealment, AKS pod identity, cloud provider detection
- **CRD** (4 checks): missing validation schema, conversion webhook security, cert-manager expiry, cert-manager insecure config

#### Auto-Remediation Engine
- `kubevigil fix` command with 20 auto-fixable checks
- Comment-preserving YAML round-trip patching via `yaml.v3` Node API
- Five-ring safety model: dry-run default, risk-level gating, system namespace hard block, interactive confirmation, mandatory backup
- Three risk levels: safe (7 checks), likely safe (9 checks), potentially breaking (4 checks)
- Dry-run mode with unified diff preview (ANSI colored)
- Backup and restore with timestamped snapshots and `RESTORE.md`
- Known workload detection (CNI, storage drivers, exporters) to avoid breaking system components
- Fix verification via `--verify` (re-scan after patching)
- Structured exit codes: 0 (success), 1 (verify found remaining), 2 (error), 3 (config error), 4 (nothing to fix), 5 (partial success)

#### Fix Output Generators
- Kustomize overlay generation (`--kustomize`)
- Helm `values.yaml` security defaults (`--output helm-values`)
- `kubectl patch` command generation (`--output kubectl`)
- Markdown fix report (`--report`)
- GitOps PR generation via `gh`/`glab` (`--git-pr`)
- Unified diff output (`--output diff`)

#### Compliance Mapping
- CIS Kubernetes Benchmark v1.8 (control ID mapping for all applicable checks)
- MITRE ATT&CK for Containers v14 (tactic and technique mapping)
- NSA/CISA Kubernetes Hardening Guide v1.2 (section mapping)
- Framework-based filtering with `--framework`

#### Output Formats (8 formats)
- **Text** — colored terminal output with severity indicators
- **JSON** — structured findings with full metadata
- **YAML** — structured findings in YAML format
- **Markdown** — formatted report with tables
- **HTML** — interactive SaaS-style dashboard with dark mode, posture scoring (A/B/C/D/F grades), SVG donut charts, KPI cards, compliance tabs, remediation drawer, CSV/JSON export, PDF print support
- **SARIF** — Static Analysis Results Interchange Format for GitHub Security integration
- **JUnit XML** — CI/CD test result format for Jenkins, GitLab, etc.
- **CSV** — tabular export for spreadsheet analysis

#### Executive Summary
- Posture score computation (0-100) with letter grades
- Per-category and per-severity breakdown
- Tier-based scoring (workload, access control, network, platform)
- Narrative summary generation for HTML reports

#### Configuration
- YAML config file (`.kubevigil.yaml`) with severity overrides, check enable/disable
- Per-check and per-resource exemptions
- Namespace classification (system vs user)
- Default config generation via `config.Default()`

#### CLI
- `kubevigil scan` — scan live clusters or manifests with filtering and output options
- `kubevigil fix` — auto-remediate findings with safety controls
- `kubevigil list checks` — list all available security checks
- `kubevigil version` — show version, commit SHA, and build date (via ldflags)
- Shell completion for Bash, Zsh, Fish, and PowerShell

#### Documentation
- 47 user-facing documentation files covering all features
- Godoc comments on all 21 packages and exported symbols
- CLI reference with all flags and subcommands
- E2E test report with cross-validation results

#### CI/CD
- GitHub Actions pipeline with lint, test, build, and vulnerability scanning
- Coverage badge with 90% threshold enforcement
- `golangci-lint` integration with custom config
- Makefile with build/test/lint/vet/cover/vulncheck/clean targets
- Version injection via ldflags in CI and Makefile

#### Performance
- Benchmark suite (39 benchmarks across 5 packages)
- `ExtractPodSpecs` caching via `sync.Map` + `sync.Once` (scan: 42% faster, 65% less memory)
- `ResourceCache.List()` freeze for zero-allocation reads (7.7x faster)
- Single-pass `ComputeSummary` (reports: 25% less memory)
- Flat-table LCS diff algorithm (13% faster, 32% fewer allocations)
- HTML report size reduction (~74% via dedup, columnar JSON, lazy render)

#### Testing
- 23 test packages with 93.8% line coverage
- Table-driven unit tests with 15+ cases per checker
- Contract tests verifying interface compliance for all 110 checkers
- Integration tests for scan engine, fix pipeline, and report generation
- E2E test suite: 11 scan scenarios + 9 fix scenarios via Bats framework
- Kind cluster validation across 3 cluster configurations (single-node, multi-node, HA)
- Golden workflow verification: scan → fix → re-scan → zero findings

