# Phase 3a — Foundation: Types, Finding Extension, Fix Registry, YAML Round-Trip

## Context

You are implementing Phase 3 (Auto-Remediation) of KubeVigil, a Kubernetes Security Posture Management CLI tool. Phase 1 (25 workload checks, scan engine, text+JSON output) and Phase 2 (110 total checks, 8 output formats, CIS/MITRE/NSA framework mapping) are complete.

**Read these files before doing ANYTHING:**
- `CLAUDE.md` — Project identity, coding standards, workflow rules, existing architecture
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7: Auto-Remediation Engine). Do NOT read the full file — Sections 1–6 and 8+ are Phase 1/2 specs already summarized in CLAUDE.md.
- `internal/checker/checker.go` — Current Finding struct, Checker interface, Severity types

Phase 3 adds `kubevigil fix` — an auto-remediation command that patches YAML manifests. This prompt (3a) builds the **foundation layer**: types, Finding struct extension, fix registry, and YAML round-trip library setup.

## Objectives

### 1. Extend the Finding Struct

The current `Finding` struct in `internal/checker/checker.go` is missing fields needed for auto-remediation. Add:

```go
type Finding struct {
    // ... ALL existing fields (do NOT remove or rename anything) ...
    
    // NEW — Phase 3 fields for auto-remediation
    CurrentValue interface{} `json:"current_value,omitempty" yaml:"current_value"`
    DesiredValue interface{} `json:"desired_value,omitempty" yaml:"desired_value"`
    FixHint      *FixHint    `json:"fix_hint,omitempty" yaml:"fix_hint"`
}
```

**CRITICAL:** This is a backward-compatible extension. Existing checkers that don't populate these fields continue to work. All existing tests MUST pass without modification. Run `go test ./...` after making this change.

### 2. Define Fix Types

Create `internal/fix/types.go` with:

```go
package fix

type FixSafety string
const (
    FixSafe                FixSafety = "safe"
    FixLikelySafe          FixSafety = "likely_safe"
    FixPotentiallyBreaking FixSafety = "potentially_breaking"
    FixManualOnly          FixSafety = "manual_only"
)

type FixOp string
const (
    FixOpSet    FixOp = "set"    // Set field to value
    FixOpAdd    FixOp = "add"    // Add field (doesn't exist yet)
    FixOpRemove FixOp = "remove" // Remove field
    FixOpMerge  FixOp = "merge"  // Merge into existing map/list
)

type FixHint struct {
    Safety      FixSafety `json:"safety" yaml:"safety"`
    Description string    `json:"description" yaml:"description"`
    Impact      string    `json:"impact,omitempty" yaml:"impact"`
    Operation   FixOp     `json:"operation" yaml:"operation"`
}

type RiskLevel string
const (
    RiskLevelSafe       RiskLevel = "safe"
    RiskLevelModerate   RiskLevel = "moderate"
    RiskLevelAggressive RiskLevel = "aggressive"
)

// FixResult represents the outcome of a single fix application.
type FixResult struct {
    FilePath    string   `json:"file_path"`
    Resource    string   `json:"resource"`
    Namespace   string   `json:"namespace,omitempty"`
    Kind        string   `json:"kind"`
    CheckID     string   `json:"check_id"`
    Safety      FixSafety `json:"safety"`
    Description string   `json:"description"`
    Impact      string   `json:"impact,omitempty"`
    Applied     bool     `json:"applied"`
    SkipReason  string   `json:"skip_reason,omitempty"` // "system_namespace", "risk_too_high", "manual_only", etc.
}

// FixSummary is the aggregate result of a fix operation.
type FixSummary struct {
    FilesScanned   int          `json:"files_scanned"`
    FilesModified  int          `json:"files_modified"`
    TotalFindings  int          `json:"total_findings"`
    Applied        int          `json:"applied"`
    Skipped        int          `json:"skipped"`
    ByRisk         map[FixSafety]int `json:"by_risk"`
    SkipReasons    map[string]int    `json:"skip_reasons"`
    Results        []FixResult  `json:"results"`
    BackupDir      string       `json:"backup_dir,omitempty"`
}
```

### 3. Create Fix Strategy Registry

Create `internal/fix/registry.go` — a mapping from check IDs to their fix strategies. This tells the fixer HOW to fix each check.

```go
type FixStrategy struct {
    CheckID     string
    Safety      FixSafety
    Operation   FixOp
    FieldPath   string      // Template: "spec.containers[*].securityContext.privileged"
    DesiredValue interface{} // The value to set
    Description string
    Impact      string
}

type FixRegistry struct {
    strategies map[string]FixStrategy
}
```

Register fix strategies for ALL checks that are auto-fixable. Organize by category:

**Safe fixes (examples):**
- `privileged`: set `securityContext.privileged` to `false`
- `privilege-escalation`: set `allowPrivilegeEscalation` to `false`
- `automount-token`: set `automountServiceAccountToken` to `false`

**Likely safe fixes (examples):**
- `capabilities-not-dropped`: add `drop: ["ALL"]` to capabilities
- `run-as-root`: set `runAsNonRoot` to `true`
- `read-only-rootfs`: set `readOnlyRootFilesystem` to `true`

**Potentially breaking fixes (examples):**
- `resource-limits-missing`: add default limits (values are opinionated)
- `host-ports`: remove hostPort (could break NodePort-style access)

**Manual only (examples):**
- `rbac-wildcard-verbs`: RBAC restructuring
- `network-policy-missing`: requires designing NetworkPolicy
- `secrets-in-env`: requires architectural change to volume mounts

Not every check needs a fix strategy. Some checks (info-level, absence-based) are inherently manual-only.

### 4. YAML Round-Trip Library Setup

The YAML patcher is the hardest technical challenge. Set up the foundation:

- Use `gopkg.in/yaml.v3` Node API for round-trip parsing
- Create `internal/fix/yaml_patcher.go` with core functions:
  - `ParseYAMLPreservingFormat(data []byte) (*yaml.Node, error)` — parse YAML preserving all formatting
  - `SerializeNode(node *yaml.Node) ([]byte, error)` — serialize back preserving format
  - `FindNode(root *yaml.Node, path string) (*yaml.Node, error)` — navigate to a field by path
  - `SetNode(root *yaml.Node, path string, value interface{}) error` — set a field value
  - `AddNode(root *yaml.Node, path string, value interface{}) error` — add a new field
  - `RemoveNode(root *yaml.Node, path string) error` — remove a field
- Handle multi-document YAML (`---` separators)
- Preserve: comments (inline, head, foot), blank lines, key ordering, indentation style (2-space, 4-space), quoting style

### 5. System Namespace and Known Workload Detection

Create `internal/fix/safety.go` and `internal/fix/known_workloads.go`:

**System namespaces** (built-in list, extensible via config):
```go
var DefaultSystemNamespaces = []string{
    "kube-system", "kube-public", "kube-node-lease",
    "rook-ceph", "rook-ceph-system",
    "calico-system", "calico-apiserver", "tigera-operator",
    "cilium", "cilium-system",
    "ingress-nginx", "traefik", "traefik-system",
    "cert-manager",
    "monitoring", "prometheus", "grafana",
    "istio-system", "linkerd", "linkerd-cni",
    "metallb-system", "longhorn-system", "openebs",
}
```

**Known workload detection** by image name patterns:
```go
var KnownSystemWorkloads = []KnownWorkload{
    {Pattern: "calico/node", Reason: "CNI plugin requires elevated privileges"},
    {Pattern: "cilium/cilium", Reason: "CNI plugin requires elevated privileges"},
    {Pattern: "flannel/flannel", Reason: "CNI plugin requires host networking"},
    {Pattern: "rook/ceph", Reason: "Storage operator requires privileged access"},
    {Pattern: "rancher/local-path-provisioner", Reason: "Storage provisioner needs host paths"},
    {Pattern: "registry.k8s.io/kube-proxy", Reason: "kube-proxy requires host networking"},
    {Pattern: "registry.k8s.io/coredns", Reason: "CoreDNS needs NET_BIND_SERVICE"},
    {Pattern: "prom/node-exporter", Reason: "Node exporter requires host PID/network"},
    // ... more patterns
}
```

## Testing Requirements — TDD is Mandatory

### Test-First Approach

For EVERY file, write the test FIRST, watch it fail, then implement.

### Required Tests

1. **`internal/fix/types_test.go`** — Verify type constants, FixSafety ordering, FixHint JSON serialization
2. **`internal/fix/registry_test.go`** — Verify all registered strategies, strategy lookup by check ID, unknown check returns nil
3. **`internal/fix/yaml_patcher_test.go`** — THE critical test file:
   - Round-trip: parse → serialize → output matches input exactly (byte-for-byte for simple cases)
   - Comment preservation: inline comments, head comments, foot comments
   - Blank line preservation
   - Key ordering preservation (keys stay in original order, not alphabetized)
   - Multi-document YAML handling
   - FindNode navigates correctly
   - SetNode changes value without disturbing formatting
   - AddNode adds field with correct indentation
   - RemoveNode removes without leaving artifacts
   - Edge cases: empty documents, documents with only comments, deeply nested paths
4. **`internal/fix/safety_test.go`** — System namespace detection, known workload detection, configurable overrides
5. **`internal/fix/known_workloads_test.go`** — Image pattern matching, reason strings
6. **Existing test suite MUST still pass** — Run `go test ./...` and verify zero regressions. The Finding struct extension is backward-compatible.

### Test Fixtures

Create `test/fixtures/fix/` directory with:
- `simple-deployment.yaml` — basic deployment with security issues
- `commented-deployment.yaml` — deployment with extensive comments
- `multi-doc.yaml` — multiple YAML documents separated by `---`
- `complex-indentation.yaml` — mixed indentation styles
- `already-secure.yaml` — deployment with no findings (negative test)

## Tasks Integration

File tasks issues for each component:
- `phase3-finding-extension` — Extend Finding struct
- `phase3-fix-types` — Define fix types
- `phase3-fix-registry` — Fix strategy registry
- `phase3-yaml-patcher` — YAML round-trip patcher
- `phase3-safety-classification` — Safety and known workload detection

Set dependencies: yaml-patcher depends on fix-types. fix-registry depends on fix-types.

## Quality Gates

Before considering this prompt complete:
1. `go test ./...` passes (ALL tests, including Phase 1 and 2)
2. `go vet ./...` clean
3. `golangci-lint run` clean
4. All new code has godoc comments
5. Test coverage for new code ≥ 85%
6. YAML round-trip tests pass with comment/format preservation verified
7. Tasks issues filed and updated
8. `git push` to remote

## Files Created/Modified

### New Files
- `internal/fix/types.go` + `types_test.go`
- `internal/fix/registry.go` + `registry_test.go`
- `internal/fix/yaml_patcher.go` + `yaml_patcher_test.go`
- `internal/fix/safety.go` + `safety_test.go`
- `internal/fix/known_workloads.go` + `known_workloads_test.go`
- `test/fixtures/fix/*.yaml`

### Modified Files
- `internal/checker/checker.go` — Add CurrentValue, DesiredValue, FixHint to Finding
- `go.mod` / `go.sum` — If yaml.v3 not already a dependency (check first)
