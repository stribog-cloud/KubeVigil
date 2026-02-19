# PROMPT — Code Comments Completion (Godoc Compliance)

> **Role:** You are a documentation completionist. Your single mandate is to bring every Go package in KubeVigil to godoc compliance by adding package-level doc comments and any remaining exported-symbol doc comments. You change **zero behavior** — comments only.

---

## Pre-Flight

**Read these files first:**

- `CLAUDE.md` — Project identity, architecture overview
- `AGENTS.md` — Tasks workflow, session completion rules

**Ground rules:**

- **Comments only.** Do not change any code behavior. Not a single logic line.
- **Tests are off-limits.** Do not touch `*_test.go` or `*bench_test.go` files.
- **Coverage must not change.** Comments don't affect coverage, but verify at the end.
- **TDD does not apply** (no code changes), but verification does — run `go vet ./...` and `go doc` spot-checks.
- **Tasks is mandatory.** File one issue before starting, close it when done.
- **Follow AGENTS.md** for session completion (commit, push).
- **Go doc conventions:** https://go.dev/doc/comment — every comment starts with the identifier name.

---

## Scope: Package-Level Doc Comments

**19 packages are missing a `// Package <name> ...` comment.** Each needs one added to its primary file (the file that best represents the package's purpose). Do NOT create `doc.go` files — add the comment directly above the `package` declaration in the most representative file.

Here is the exact list with guidance on what each comment should convey:

### Core Packages

| Package | Primary File | Comment Should Describe |
|---------|-------------|------------------------|
| `cmd/kubevigil` | `main.go` | CLI entry point, Cobra command tree, available subcommands (scan, fix, list, version) |
| `internal/engine` | `scanner.go` | Scan orchestration — manifest parsing, live-cluster fetching, concurrent check execution, result assembly |
| `internal/checker` | `checker.go` | Checker framework — Checker interface, Finding type, ResourceCache, severity model, scan modes |
| `internal/config` | `config.go` | Configuration loading — YAML config file parsing, severity overrides, exemptions, scan settings |
| `internal/fix` | `fixer.go` | Auto-remediation engine — fix planning, YAML patching, dry-run, backup, Kustomize/Helm overlay generation, GitOps integration |
| `internal/report` | `reporter.go` | Report generation — multi-format output (text, JSON, HTML, SARIF, Markdown, JUnit, CSV, YAML), posture scoring, compliance mapping |
| `internal/frameworks` | `mapping.go` | Compliance framework mappings — CIS Kubernetes Benchmark, NSA Hardening Guide, MITRE ATT&CK for Containers |
| `internal/k8s` | `client.go` | Kubernetes client construction — kubeconfig loading, context selection, dynamic client and discovery client setup |

### Checker Sub-Packages (one per security domain)

| Package | Primary File | Comment Should Describe |
|---------|-------------|------------------------|
| `internal/checker/workload` | `register.go` | Workload security checks — container privileges, capabilities, security contexts, resource limits, host access, runtime policies (24 checks) |
| `internal/checker/rbac` | `register.go` | RBAC security checks — role permissions, cluster-admin usage, wildcard access, service account hygiene, token projection (11 checks) |
| `internal/checker/network` | `register.go` | Network security checks — network policies, ingress configuration, service exposure, DNS security, service mesh mTLS (13 checks) |
| `internal/checker/secrets` | `register.go` | Secret management checks — secrets in env vars, configmaps, manifests, encryption at rest, rotation, external secret sync (8 checks) |
| `internal/checker/image` | `register.go` | Container image checks — tag policies, digest pinning, registry allowlists/blocklists, provenance, SBOM attestation, signatures (11 checks) |
| `internal/checker/cluster` | `register.go` | Cluster-level checks — API server config, admission controllers, audit logging, etcd encryption, component versions, resource quotas (10 checks) |
| `internal/checker/scheduling` | `register.go` | Scheduling security checks — tolerations, node affinity, priority classes, topology spread, PDB, HPA resource alignment (9 checks) |
| `internal/checker/psa` | `register.go` | Pod Security Admission checks — PSA label enforcement, baseline/restricted violations, PSP migration detection (7 checks) |
| `internal/checker/storage` | `register.go` | Storage security checks — CSI driver config, PVC reclaim policy, encryption, emptyDir limits, projected volume security (6 checks) |
| `internal/checker/supply_chain` | `register.go` | Supply chain checks — image age, container runtime sockets, lifecycle hooks, probe configuration (5 checks) |
| `internal/checker/cloud` | `register.go` | Cloud provider checks — EKS IMDS access, GKE metadata concealment, AKS pod identity, cloud IAM bindings (4 checks) |
| `internal/checker/crd` | `register.go` | CRD and extension checks — cert-manager certificate expiry/insecure config, CRD validation webhooks, conversion webhooks (4 checks) |

**Total: 20 packages × 1 comment each.**

### Comment Format

Follow this exact pattern:

```go
// Package <name> <verb-phrase describing what the package does>.
//
// <1-3 sentences expanding on scope, key types, or how it fits in the architecture.>
package <name>
```

**Example (already done correctly in internal/version):**

```go
// Package version exposes the build-time version, commit, and date metadata
// injected via ldflags during the release build process.
package version
```

**Example for a checker sub-package:**

```go
// Package workload implements security checks for Kubernetes workload resources
// including Pods, Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.
//
// It covers 24 checks spanning container privileges, Linux capabilities,
// security contexts, resource limits, host-level access, and runtime policies.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package workload
```

### Writing Guidelines

- **Read the package first.** Skim the primary file and `register.go` (if present) to understand what the package actually does. Do not guess.
- **Be specific about scope.** Include the check count for checker packages (verify by counting entries in `register.go`). Include the format list for the report package. Include the framework names for the frameworks package.
- **Reference key types.** Use Go doc link syntax `[TypeName]` for the 1-2 most important exported types in each package.
- **Keep it tight.** 2-4 lines max. Package comments are orientation, not documentation.
- **Do not duplicate.** If a file already has a `// Package` comment, do not add another one.

---

## Scope: Exported Symbol Doc Comments

After adding package comments, do a **single sweep** for any remaining exported functions, types, methods, constants, or variables that lack doc comments. Focus on:

1. **Exported types** (`type Foo struct`) — every one needs a comment starting with `// Foo ...`
2. **Exported functions** (`func Bar()`) — every one needs a comment starting with `// Bar ...`
3. **Exported methods** (`func (x *X) Baz()`) — every one needs a comment starting with `// Baz ...`
4. **Exported constants/variables** — groups can use a single block comment

**Skip:**
- Test files entirely
- Unexported (lowercase) identifiers
- Identifiers that already have comments
- Simple one-line accessor methods where the name is self-documenting AND the type is obvious (use judgment — when in doubt, add the comment)

**Detection command:**

```bash
for f in $(find internal/ cmd/ -name "*.go" -not -name "*_test.go" -not -name "*bench*" | sort); do
  awk '
    /^\/\// { comment=1; next }
    /^func [A-Z]/ { if (!comment) print FILENAME":"NR": "$0; comment=0; next }
    /^type [A-Z]/ { if (!comment) print FILENAME":"NR": "$0; comment=0; next }
    /^var [A-Z]/ { if (!comment) print FILENAME":"NR": "$0; comment=0; next }
    /^const [A-Z]/ { if (!comment) print FILENAME":"NR": "$0; comment=0; next }
    { comment=0 }
  ' "$f"
done
```

This will list every exported symbol without a preceding comment. Work through the list.

---

## Verification

After all comments are added:

```bash
# 1. Confirm zero code behavior changed
go test ./...

# 2. Confirm no vet warnings
go vet ./...

# 3. Confirm coverage unchanged
go test -coverprofile=/tmp/kv-comments.out ./...
go tool cover -func=/tmp/kv-comments.out | tail -1
# Must still be 93.8%

# 4. Spot-check godoc renders correctly
go doc ./internal/checker
go doc ./internal/engine
go doc ./internal/fix
go doc ./internal/report
go doc ./internal/checker/workload
go doc ./cmd/kubevigil

# 5. Verify all 20 packages now have package comments
for dir in $(find internal/ cmd/ -type d | sort); do
  gofiles=$(find "$dir" -maxdepth 1 -name "*.go" -not -name "*_test.go" 2>/dev/null)
  [ -z "$gofiles" ] && continue
  has_doc=false
  for f in $gofiles; do
    if head -5 "$f" | grep -q "^// Package"; then
      has_doc=true
      break
    fi
  done
  if $has_doc; then
    echo "✅ $dir"
  else
    echo "❌ $dir"
  fi
done
# Must show zero ❌
```

---

## Tasks

File a single issue before starting:

- **Title:** `godoc-comments-completion`
- **Type:** `chore`
- **Priority:** P3
- **Description:** Add package-level doc comments to all 20 packages missing them. Sweep remaining exported symbols for missing godoc comments. Comments only — zero code changes.

Close it after verification passes.

---

## Parallelization

Use **3 sub-agents** for speed:

| Agent | Scope |
|-------|-------|
| Agent 1 | Core packages (8): cmd/kubevigil, engine, checker, config, fix, report, frameworks, k8s |
| Agent 2 | Checker sub-packages (12): workload, rbac, network, secrets, image, cluster, scheduling, psa, storage, supply_chain, cloud, crd |
| Agent 3 | Exported symbol sweep + verification |

Agent 3 runs after Agents 1 and 2 complete.

---

## Completion Criteria

- [ ] All 20 packages have `// Package <name> ...` comments
- [ ] Zero exported types/functions without doc comments (excluding trivial accessors)
- [ ] `go test ./...` — all 23 packages pass
- [ ] `go vet ./...` — clean
- [ ] Coverage = 93.8% (unchanged)
- [ ] `go doc` renders correctly for all packages
- [ ] Tasks issue closed
- [ ] Git committed and pushed per AGENTS.md
