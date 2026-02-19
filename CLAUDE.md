# KubeVigil — CLAUDE.md

## Project Identity

**KubeVigil** — "Know your clusters before attackers do."

A Kubernetes Security Posture Management (KSPM) CLI tool written in Go. Open source, Apache 2.0 licensed, built by Stribog. This is also a Go learning project — the codebase should teach idiomatic Go patterns through real-world production code.

**Current Phase:** Phase 2 — Breadth

**Reference document:** `docs/kubevigil-features-v2.md` contains the complete feature specification across all 7 phases. **Read this file before making architectural decisions.** It defines all 112 security checks, testing strategy, compliance frameworks, output formats, and roadmap.

---

## Phase 1 — COMPLETE ✅

Phase 1 built the foundation. Everything below exists and works. **Do not rebuild or restructure Phase 1 code** — extend it.

### What Exists

- **25 workload security checkers** (all of Section 2.1 + ephemeral-container-policy from 2.2) — fully tested with TDD, fixtures, contract tests
- **Checker interface** — `Checker` with Name(), Description(), Categories(), SupportedModes(), RequiredResources(), Run()
- **Checker registry** — Self-registration via `init()`, global registry with Register/Get/All/Names
- **Resource cache** — `ResourceCache` with Add, List, ListNamespaced, GVRs, GVRForKind
- **Manifest parser** — ParseFile, ParseDir, ParseBytes, ParsePath with multi-doc YAML, graceful error handling
- **Scan engine** — `ScanManifest()` and `ScanLive()` orchestrators with concurrent checker execution via errgroup
- **K8s client** — Dynamic + discovery client wrapper with FetchResources, graceful GVR degradation
- **Reports** — Text (colored terminal) and JSON reporters with Reporter interface, contract tests, golden files
- **Configuration** — `.kubevigil.yaml` parsing, check enable/disable, severity overrides, exemptions (namespace/resource/kind/annotation with expiry)
- **CLI** — Cobra commands: `kubevigil scan` (--file for manifest, live cluster default), `kubevigil list checks`, `kubevigil version`
- **Exit codes** — 0 (clean), 1 (findings), 2 (scan error), 3 (config error)
- **Test infrastructure** — helpers (generators, assertions, fixture loader), integration tests, contract tests
- **Shared workload helpers** — `ExtractPodSpecs()`, `IterateContainers()` with support for regular, init, and K8s 1.28+ native sidecar containers

### Key Patterns Established (Follow These)

- **Checker pattern:** One file + one test file per check in `internal/checker/<category>/`. Test file has table-driven tests with 15+ cases. Checker uses `ExtractPodSpecs` + `IterateContainers` for workload checks.
- **Registration pattern:** Each category package has a `register.go` with `init()` that registers all checkers in that package.
- **Fixture pattern:** `test/fixtures/<check-id>/` with passing and failing YAML files for each check.
- **Test helper pattern:** `test/helpers/` has generators (functional options), assertions, fixture loaders.
- **Contract test pattern:** `test/integration/contract_test.go` iterates ALL registered checkers and verifies interface compliance.

---

## Phase 2 Scope — What to Build

### IN Scope

#### New Checks — 85 Remaining (Sections 2.3-2.13 of features doc)

| Category | Section | Check IDs | Count | Notes |
|----------|---------|-----------|-------|-------|
| Image Security | 2.3 | 28-36 | 9 | Image tag/digest/registry/signature checks. Most work in manifest mode. |
| Identity & Access (RBAC) | 2.4 | 37-51 | 15 | ServiceAccount + RBAC checks. Requires Roles, ClusterRoles, Bindings GVRs. |
| Secrets Management | 2.5 | 52-58 | 7 | Secrets in env, unencrypted etcd, hardcoded values, entropy analysis. |
| Network Security | 2.6 | 59-70 | 12 | NetworkPolicy, Ingress, Service type, service mesh mTLS, DNS security. |
| Pod Security Standards | 2.7 | 71-76 | 6 | PSA label enforcement, PSS profile validation, PSP migration. |
| Scheduling & Availability | 2.8 | 77-84 | 8 | Tolerations, PriorityClass, PDB, topology spread, HPA. |
| Storage Security | 2.9 | 85-89 | 5 | PVC encryption, reclaim policy, CSI drivers, emptyDir, projected volumes. |
| Cluster Configuration | 2.10 | 90-99 | 10 | Namespace hygiene, LimitRange, ResourceQuota, API server, etcd, kubelet. |
| Supply Chain | 2.11 | 100-104 | 5 | Runtime sockets, probes, lifecycle hooks, image age. |
| Cloud Provider | 2.12 | 105-108 | 4 | EKS IMDS, GKE metadata, AKS pod identity, auto-detection. |
| CRD Security | 2.13 | 109-112 | 4 | CRD validation, conversion webhooks, cert-manager. |

#### New Output Formats

| Format | File | Priority | Notes |
|--------|------|----------|-------|
| Markdown | `internal/report/markdown.go` | High | For PRs, wikis, documentation |
| SARIF | `internal/report/sarif.go` | High | GitHub Security tab integration |
| YAML | `internal/report/yaml.go` | Medium | K8s-native tooling |
| HTML | `internal/report/html.go` | Medium | Self-contained report with charts, search, collapsible sections |
| JUnit XML | `internal/report/junit.go` | Medium | CI systems (Jenkins etc.) |
| CSV | `internal/report/csv.go` | Low | Spreadsheet analysis |

#### CIS Benchmark Mapping

- `internal/frameworks/mapping.go` — Framework mapping types
- `internal/frameworks/cis.go` — Map each check to CIS Kubernetes Benchmark controls
- `internal/frameworks/mitre.go` — Map checks to MITRE ATT&CK techniques
- `internal/frameworks/nsa.go` — Map checks to NSA/CISA Hardening Guide
- CLI flag: `--framework cis-1.8` to filter report to framework-relevant checks only
- Report output includes framework references per finding

#### Structured Logging

- Replace any `fmt.Println` debug output with `log/slog` structured logging
- Configurable log level via `--verbose` / `--log-level`

### OUT of Scope (Later Phases — Do NOT Build)

- Auto-remediation / `kubevigil fix` (Phase 3)
- GitHub Action, baseline management, PR decoration, incremental scanning (Phase 4)
- Admission webhooks, operator mode, Prometheus metrics, Grafana (Phase 5)
- Multi-cluster, trend analysis, SQLite, Rego policies (Phase 6)
- SDK, plugin system, docs site, Helm/Krew/Homebrew distribution (Phase 7)
- Helm chart scanning, Kustomize scanning, stdin scanning, diff scan, watch mode, inventory mode
- Attack path analysis, posture scoring, scan caching (these require more infrastructure)
- PDF output (requires external library, defer to later)

---

## Architecture — Phase 2 Additions

### New Checker Categories

Phase 2 adds 11 new checker packages under `internal/checker/`:

```
internal/checker/
├── workload/        # ✅ Phase 1 — 25 checks (DO NOT MODIFY unless bug)
├── image/           # NEW — 9 checks (image tag, digest, registry, signatures)
├── rbac/            # NEW — 15 checks (ServiceAccount, Roles, Bindings)
├── secrets/         # NEW — 7 checks (env secrets, encryption, entropy)
├── network/         # NEW — 12 checks (NetworkPolicy, Ingress, Service, mesh)
├── psa/             # NEW — 6 checks (PSA labels, PSS profiles, PSP)
├── scheduling/      # NEW — 8 checks (tolerations, priority, PDB, HPA)
├── storage/         # NEW — 5 checks (PVC, CSI, emptyDir, projected volumes)
├── cluster/         # NEW — 10 checks (namespace, quotas, API server, etcd)
├── supply_chain/    # NEW — 5 checks (runtime sockets, probes, image age)
├── cloud/           # NEW — 4 checks (EKS, GKE, AKS, auto-detect)
└── crd/             # NEW — 4 checks (CRD validation, cert-manager)
```

Each package follows the established pattern:
- One file + one test file per check
- `register.go` with `init()` to register all checks
- Test fixtures in `test/fixtures/<check-id>/`

### New Resource Types Needed

Phase 2 checks require additional K8s resource types in the ResourceCache. The `GVRForKind()` helper in `internal/checker/resource_cache.go` needs to be extended for:

- `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding` (rbac.authorization.k8s.io/v1)
- `NetworkPolicy` (networking.k8s.io/v1)
- `Ingress` (networking.k8s.io/v1)
- `ServiceAccount` (v1)
- `Service` (v1)
- `Secret`, `ConfigMap` (v1)
- `LimitRange`, `ResourceQuota` (v1)
- `PersistentVolumeClaim`, `PersistentVolume` (v1)
- `StorageClass` (storage.k8s.io/v1)
- `CSIDriver` (storage.k8s.io/v1)
- `PodDisruptionBudget` (policy/v1)
- `HorizontalPodAutoscaler` (autoscaling/v2)
- `PriorityClass` (scheduling.k8s.io/v1)
- `CustomResourceDefinition` (apiextensions.k8s.io/v1)
- `PodSecurityPolicy` (deprecated, but need to detect lingering ones)
- `Node` (v1)

### RBAC Checks — Special Architecture Note

RBAC checks are fundamentally different from workload checks. They don't iterate containers — they analyze Role/ClusterRole rules and RoleBinding/ClusterRoleBinding subjects. The shared `ExtractPodSpecs`/`IterateContainers` helpers do NOT apply.

For RBAC checks:
- Write new helpers in `internal/checker/rbac/helpers.go` for common RBAC analysis patterns
- E.g., `ExtractRules(cache)` returns all Role + ClusterRole rules
- E.g., `FindBindingsForRole(cache, roleName)` finds all bindings referencing a role
- RBAC checks need both Roles AND Bindings to analyze effectively

### Network Checks — Special Architecture Note

Network checks analyze NetworkPolicy, Ingress, and Service resources. Some checks (like `network-policy-missing`) operate at the namespace level, not the resource level — they check for the ABSENCE of a resource.

For namespace-level checks:
- The checker needs to list all namespaces and check whether a matching resource exists
- Finding should reference the namespace, not a specific resource

### Secrets Checks — Special Architecture Note

`secrets-in-configmap` (check 54) uses entropy analysis to detect potential secrets in ConfigMap values. Implement Shannon entropy calculation in a helper. High entropy strings (>4.5 bits/char) with length >16 are likely secrets. Also pattern-match known formats (JWT `eyJ`, AWS key `AKIA`, private key headers `-----BEGIN`).

### Framework Mapping Types

```go
type FrameworkRef struct {
    Framework string  // "cis", "mitre", "nsa"
    Version   string  // "1.8", "v14", "1.2"
    ControlID string  // "5.2.1", "T1611", etc.
    Title     string  // Human-readable control title
}

// Add to Finding struct:
type Finding struct {
    // ... existing fields from Phase 1 ...
    Frameworks []FrameworkRef  // NEW — compliance framework references
}
```

---

## Phase 2 Checks — Complete List

### 2.3 Image Security (internal/checker/image/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 28 | `image-tag-latest` | Medium |
| 29 | `image-tag-missing` | Medium |
| 30 | `image-no-digest` | Low |
| 31 | `image-pull-policy` | Medium |
| 32 | `image-registry-allowlist` | High |
| 33 | `image-registry-blocklist` | Critical |
| 34 | `image-signature-verification` | Medium |
| 35 | `image-sbom-attestation` | Low |
| 36 | `image-provenance` | Low |

### 2.4 Identity & Access — RBAC (internal/checker/rbac/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 37 | `default-service-account` | High |
| 38 | `automount-token` | High |
| 39 | `token-projection-config` | Medium |
| 40 | `rbac-wildcard-verbs` | Critical |
| 41 | `rbac-wildcard-resources` | Critical |
| 42 | `rbac-wildcard-apigroups` | Critical |
| 43 | `rbac-escalation-verbs` | Critical |
| 44 | `rbac-secret-access` | High |
| 45 | `rbac-exec-access` | High |
| 46 | `rbac-log-access` | Medium |
| 47 | `rbac-cluster-admin` | Critical |
| 48 | `rbac-unused-roles` | Info |
| 49 | `rbac-group-bindings` | High |
| 50 | `rbac-subject-external` | Low |
| 51 | `cloud-iam-binding` | Medium |

### 2.5 Secrets Management (internal/checker/secrets/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 52 | `secrets-in-env` | Medium |
| 53 | `secrets-unencrypted` | Critical |
| 54 | `secrets-in-configmap` | High |
| 55 | `secrets-default-type` | Low |
| 56 | `secrets-stale` | Medium |
| 57 | `secrets-hardcoded-manifests` | High |
| 58 | `external-secrets-sync` | Medium |

### 2.6 Network Security (internal/checker/network/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 59 | `network-policy-missing` | High |
| 60 | `network-policy-default-deny` | High |
| 61 | `network-policy-overly-permissive` | Medium |
| 62 | `network-policy-egress-unrestricted` | Medium |
| 63 | `ingress-no-tls` | High |
| 64 | `ingress-wildcard-host` | Medium |
| 65 | `ingress-class-missing` | Low |
| 66 | `service-type-loadbalancer` | Medium |
| 67 | `service-type-nodeport` | Medium |
| 68 | `external-ips` | High |
| 69 | `service-mesh-mtls` | High |
| 70 | `dns-security` | Medium |

### 2.7 Pod Security Standards (internal/checker/psa/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 71 | `psa-labels-missing` | Medium |
| 72 | `psa-mode-audit-only` | Medium |
| 73 | `psa-baseline-violations` | High |
| 74 | `psa-restricted-violations` | Medium |
| 75 | `psa-version-pinning` | Low |
| 76 | `psp-still-present` | Info |

### 2.8 Scheduling & Availability (internal/checker/scheduling/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 77 | `toleration-control-plane` | High |
| 78 | `toleration-all` | Medium |
| 79 | `priority-class-system` | High |
| 80 | `priority-class-missing` | Low |
| 81 | `pod-disruption-budget` | Low |
| 82 | `topology-spread` | Low |
| 83 | `node-affinity-untrusted` | Medium |
| 84 | `hpa-without-requests` | Medium |

### 2.9 Storage Security (internal/checker/storage/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 85 | `pvc-no-encryption` | Medium |
| 86 | `pvc-reclaim-retain` | Medium |
| 87 | `csi-driver-security` | Low |
| 88 | `emptydir-size-limit` | Low |
| 89 | `projected-volume-security` | Medium |

### 2.10 Cluster Configuration (internal/checker/cluster/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 90 | `namespace-default-usage` | Medium |
| 91 | `limit-range-missing` | Low |
| 92 | `resource-quota-missing` | Low |
| 93 | `api-server-anonymous` | High |
| 94 | `audit-logging` | High |
| 95 | `admission-controllers` | Medium |
| 96 | `etcd-encryption` | Critical |
| 97 | `kubelet-config` | High |
| 98 | `component-versions` | Medium |
| 99 | `deprecated-api-usage` | Medium-Low |

### 2.11 Supply Chain (internal/checker/supply_chain/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 100 | `container-runtime-socket` | Critical |
| 101 | `liveness-readiness-probes` | Low |
| 102 | `startup-probes` | Info |
| 103 | `lifecycle-hooks` | Low |
| 104 | `image-age` | Low |

### 2.12 Cloud Provider (internal/checker/cloud/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 105 | `eks-imds-access` | High |
| 106 | `gke-metadata-concealment` | High |
| 107 | `aks-pod-identity` | Medium |
| 108 | `cloud-provider-detection` | Info |

### 2.13 CRD Security (internal/checker/crd/)

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 109 | `crd-validation-missing` | Medium |
| 110 | `crd-conversion-webhook` | High |
| 111 | `cert-manager-expiry` | High |
| 112 | `cert-manager-insecure` | Medium |

---

## Implementation Order — Phase 2

### Step 1: Extend Resource Cache + GVR Mappings
- Add all new K8s resource GVRs to `GVRForKind()`
- Add helper methods to ResourceCache for new resource types if needed
- Tests for new GVR mappings
- **No new checkers yet** — just infrastructure

### Step 2: Image Security Checks (9 checks)
- Simplest new category — reuses `ExtractPodSpecs` + `IterateContainers` to inspect container images
- Good bridge from Phase 1 workload patterns
- Checks 28-36

### Step 3: RBAC Checks (15 checks)
- New analysis pattern — operates on Roles/Bindings, NOT containers
- Write `internal/checker/rbac/helpers.go` for shared RBAC analysis
- Checks 37-51

### Step 4: Secrets Management Checks (7 checks)
- Mix of container-level (secrets-in-env) and cluster-level (etcd encryption) checks
- Implement Shannon entropy helper for configmap secret detection
- Checks 52-58

### Step 5: Network Security Checks (12 checks)
- New resource types: NetworkPolicy, Ingress, Service
- Namespace-level absence checks (policy-missing)
- Checks 59-70

### Step 6: Pod Security Standards Checks (6 checks)
- Namespace label analysis + workload PSS profile matching
- Checks 71-76

### Step 7: Remaining Checks — Scheduling, Storage, Cluster, Supply Chain, Cloud, CRD (30 checks)
- Group into agent teams by category
- Checks 77-112

### Step 8: CIS Benchmark & Framework Mapping
- `internal/frameworks/` — mapping types, CIS, MITRE, NSA mappers
- Add `Frameworks []FrameworkRef` to Finding struct
- Wire into existing checkers — each checker gets framework refs
- `--framework` CLI flag to filter output by framework
- Tests: every check maps to at least one framework

### Step 9: New Output Formats
- Markdown, SARIF, YAML, HTML, JUnit, CSV reporters
- Reporter contract tests (extend existing)
- Golden file tests for each format
- `--output` flag extended to accept all formats
- SARIF schema validation test

### Step 10: Structured Logging + Polish
- `log/slog` integration throughout
- Update contract test to verify all 112 checkers
- Update README with full check table
- Integration tests for new checks with manifest scan pipeline
- Final verification: `make check` passes

---

## Coding Standards

### Go Standards (Unchanged from Phase 1)

- **Go 1.22+**, module `github.com/stribog-cloud/kubevigil`
- `gofmt` + `goimports`, `golangci-lint`
- Wrap errors: `fmt.Errorf("loading config: %w", err)`
- `log/slog` for logging. No `fmt.Println`.
- Godoc comments on all exported types/functions
- Minimize dependencies. Standard library preferred.

### Phase 2 Additional Dependencies (if needed)

- `github.com/owenrumney/go-sarif/v2` — SARIF output generation (evaluate: might be simpler to hand-write given our needs)
- No other new dependencies without justification.

### Code Organization Rules (Unchanged)

- One file + one test file per checker
- `register.go` per category package
- Test fixtures in `test/fixtures/<check-id>/`
- Contract tests verify ALL registered checkers

---

## Testing Rules (Non-Negotiable)

### TDD is mandatory. Same rules as Phase 1.

Red → Green → Refactor. Fixtures first, tests first, implementation last.

### Phase 2 Test Additions

- **RBAC check tests** need Role + ClusterRole + Binding fixtures (not just workload YAML)
- **Network check tests** need NetworkPolicy + Ingress + Service fixtures
- **Namespace-level check tests** need fixtures that demonstrate resource ABSENCE
- **Secrets entropy tests** need ConfigMap fixtures with known-high-entropy values
- **SARIF output tests** must validate against SARIF 2.1.0 JSON schema
- **Framework mapping tests** must verify every check has at least one framework reference

### Coverage Targets

- Line coverage: ≥ 85%
- All 112 checkers registered and contract-tested
- Every check has fixtures
- All reporters contract-tested

---

## Workflow Rules (Unchanged from Phase 1)

### Planning
- Plan mode for ANY non-trivial task
- Stop and re-plan if something goes sideways

### Parallel Execution
- Use subagents for independent checkers
- Use agent teams for cross-cutting work (framework mapping, reporters)
- Lead orchestrates, does NOT write code

### Task Tracking (Tasks)
```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress
bd close <id>
bd sync
```

### Session Completion
1. File tasks issues for remaining work
2. Quality gates: `go test ./...`, `go vet ./...`, `golangci-lint run`
3. Update tasks status
4. **Push to remote — MANDATORY:**
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # Must show "up to date with origin"
   ```
5. Provide context for next session

**Work is NOT complete until `git push` succeeds.**

### Self-Improvement
- After ANY correction: tasks issue with `lesson` label
- Review lessons at session start

---

## Key Decisions (Pre-Made)

All Phase 1 decisions remain. Additional for Phase 2:

- **SARIF generation:** Evaluate `go-sarif` library first. If too heavy, hand-write the JSON (SARIF is just JSON with a schema).
- **HTML report:** Self-contained, inline CSS/JS, no external dependencies. Use Go `html/template`.
- **Framework data:** Hardcode mappings in Go (not external YAML/JSON files). CIS control IDs are stable across versions.
- **Entropy detection threshold:** Shannon entropy > 4.5 bits/char AND string length > 16 chars. Configurable.
- **Cloud provider detection:** Auto-detect from node labels. Don't require manual `--cloud-provider` flag.

---

## Reminders

- **Read `docs/kubevigil-features-v2.md`** for detailed check descriptions, severity rationale, and edge cases. This CLAUDE.md has check IDs and severities but the features doc has the full behavioral specification.
- **RBAC checks are architecturally different** from workload checks. Don't try to force them through ExtractPodSpecs. Write proper RBAC helpers.
- **Network and cluster checks may operate at namespace level** (checking for absence of resources). Handle this pattern correctly.
- **The contract test must pass for ALL 112 checkers** by end of Phase 2.
- **Phase 1 code is stable.** Don't refactor it unless you find a bug. Extend, don't rewrite.
- **The architecture must cleanly support Phase 3** (auto-remediation) — findings should carry enough context (field paths, current values, desired values) that a fixer can generate patches.
