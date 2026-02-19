# PROMPT — Comprehensive User Documentation

> **Purpose:** Create production-grade user documentation for KubeVigil covering all features across Phase 1, 2, and 3. The documentation must serve everyone from a first-time user scanning their first YAML file to a platform engineer integrating KubeVigil into enterprise CI/CD pipelines. Accuracy is non-negotiable — every command, flag, exit code, and behavior described must match the actual implementation. When in doubt, run the binary and verify.

---

## Pre-Flight

**Read these files before doing ANYTHING:**

- `CLAUDE.md` — Project identity, phases, architecture
- `AGENTS.md` — Tasks workflow, session completion rules
- `README.md` — Current state of user-facing documentation (886 lines, monolithic)
- `docs/internal/kubevigil-features-v3.md` — Internal feature specification (reference for accuracy, NOT the docs themselves)

**Then explore the codebase to build your understanding:**

```bash
# See the CLI surface
go run ./cmd/kubevigil --help
go run ./cmd/kubevigil scan --help
go run ./cmd/kubevigil fix --help
go run ./cmd/kubevigil list checks --help

# See the full checker list
go run ./cmd/kubevigil list checks

# See the config structure
grep -A 60 "type Config struct" internal/config/config.go

# See the exemption structure
cat internal/config/exemptions.go

# See output formats
ls internal/report/

# See fix safety types
grep -A 20 "type FixSafety" internal/fix/types.go
grep -A 30 "type FixConfig struct" internal/config/config.go

# See framework mappings
ls internal/frameworks/
```

**Accuracy rule:** For EVERY command example, flag description, or behavioral claim you write, verify it by either:
1. Running the actual command and observing the output, OR
2. Reading the source code that implements the behavior

Never write documentation from memory or assumption. If you're unsure about a flag's default value, read the Cobra flag definition. If you're unsure about an exit code, read the code that returns it.

---

## Phase A: Audit Existing Documentation

### A1. Inventory Current State

Catalog everything that exists in `docs/`:

```bash
find docs/ -name "*.md" -not -path "*/prompts/*" | sort
cat README.md | wc -l
```

### A2. Classify Existing Content

For each existing file, determine:
- **Keep and enhance** — good content that needs expansion or restructuring
- **Keep as-is** — correct and complete (e.g., internal specs)
- **Supersede** — will be replaced by new, better documentation
- **Archive** — internal/developer docs that shouldn't be in user docs path

### A3. Gap Analysis

Compare what exists against the documentation plan in Phase B. Identify every gap. This becomes your Tasks issue list.

---

## Phase B: Documentation Plan

### B1. Target Structure

The documentation lives in `docs/` as a collection of interconnected Markdown files. The structure below is the target — you will create an `index.md` that serves as the documentation home page with links to every section.

```
docs/
├── index.md                          # Documentation home — table of contents, navigation
├── getting-started/
│   ├── installation.md               # Every installation method
│   ├── quickstart.md                 # First scan in 5 minutes
│   └── understanding-output.md       # Reading and interpreting results
├── scanning/
│   ├── manifest-scanning.md          # Scanning YAML files and directories
│   ├── live-cluster-scanning.md      # Scanning running clusters
│   ├── filtering.md                  # Namespace, severity, check, framework filters
│   └── output-formats.md            # Every output format with examples
├── checks/
│   ├── overview.md                   # How checks work, categories, severity levels
│   ├── workload-security.md          # All 24 workload checks
│   ├── image-security.md             # All 9 image checks
│   ├── rbac.md                       # All 15 RBAC checks
│   ├── secrets.md                    # All 7 secrets checks
│   ├── network-security.md           # All 12 network checks
│   ├── pod-security-standards.md     # All 6 PSA checks
│   ├── scheduling.md                 # All 8 scheduling checks
│   ├── storage.md                    # All 5 storage checks
│   ├── cluster-config.md             # All 10 cluster checks
│   ├── supply-chain.md               # All 6 supply chain checks
│   ├── cloud-provider.md             # All 4 cloud checks
│   └── crd-security.md              # All 4 CRD checks
├── auto-fix/
│   ├── overview.md                   # What auto-fix does, safety philosophy
│   ├── safety-model.md               # Five-ring model in depth
│   ├── usage-guide.md                # Common workflows, flag combinations
│   ├── gitops-integration.md         # Kustomize, Helm, git-pr workflows
│   └── check-fix-reference.md       # Every auto-fixable check: what it changes, risk level
├── compliance/
│   ├── overview.md                   # Framework mapping concept
│   ├── cis-benchmark.md              # CIS Kubernetes Benchmark mapping
│   ├── mitre-attack.md               # MITRE ATT&CK mapping
│   └── nsa-cisa.md                   # NSA/CISA Hardening Guide mapping
├── configuration/
│   ├── config-file.md                # Complete .kubevigil.yaml reference
│   ├── exemptions.md                 # Exemption rules, annotation-based exemptions
│   └── policies.md                   # Custom policies (registry allowlists, etc.)
├── integrations/
│   ├── ci-cd.md                      # GitHub Actions, GitLab CI, Jenkins, Argo CD
│   ├── sarif-github.md               # GitHub Security tab integration
│   └── ide-integration.md           # VS Code, SARIF viewers
├── reference/
│   ├── cli-reference.md              # Complete flag reference for every command
│   ├── exit-codes.md                 # All exit codes for scan and fix
│   └── environment-variables.md     # Any env vars that affect behavior
├── troubleshooting/
│   └── faq.md                        # Common issues, error messages, solutions
├── architecture/
│   └── overview.md                   # How KubeVigil works internally (advanced)
└── contributing/
    └── development.md                # Building from source, running tests, adding checks
```

**Total: ~35 documentation files across 10 sections.**

### B2. Documentation Principles

Every page must follow these principles:

1. **Lead with the user's goal.** Start every page with WHAT the user wants to accomplish, not what the feature is. "You want to scan your Kubernetes manifests for security issues" not "KubeVigil's manifest scanning engine supports..."

2. **Working examples first.** Every concept gets a concrete, copy-pasteable example before the explanation. Users learn by doing. The example should WORK — test it.

3. **Progressive disclosure.** Start simple, add complexity. The quickstart shows `kubevigil scan -f deployment.yaml`. The filtering guide shows `--severity high --framework cis --namespace production`. The configuration reference shows the full YAML spec.

4. **Three audience layers.** Each page should serve:
   - **Beginner:** Clear, jargon-free explanation. What is this? Why would I use it?
   - **Practitioner:** Practical how-to. Common workflows. Copy-paste commands.
   - **Expert:** Edge cases, advanced flags, integration patterns, architecture details.

5. **No dead links.** Every cross-reference must point to a real file. Verify after writing.

6. **No stale information.** If a flag exists in the help text, it must be in the docs. If a flag is in the docs, it must exist in the help text. Cross-verify.

---

## Phase C: File Tasks Issues

**Before writing a single line of documentation**, file ALL Tasks issues.

Group issues logically — one per documentation section or major deliverable:

| Issue Title | Scope | Effort |
|---|---|---|
| `docs-index-and-structure` | Create docs/ directory structure, index.md | S |
| `docs-getting-started` | installation.md, quickstart.md, understanding-output.md | M |
| `docs-scanning` | manifest-scanning.md, live-cluster-scanning.md, filtering.md, output-formats.md | L |
| `docs-checks-overview` | checks/overview.md (categories, severity, modes) | M |
| `docs-checks-workload-image` | workload-security.md, image-security.md | L |
| `docs-checks-rbac-secrets` | rbac.md, secrets.md | L |
| `docs-checks-network-psa` | network-security.md, pod-security-standards.md | L |
| `docs-checks-scheduling-storage` | scheduling.md, storage.md | M |
| `docs-checks-cluster-supply-cloud-crd` | cluster-config.md, supply-chain.md, cloud-provider.md, crd-security.md | L |
| `docs-auto-fix` | All auto-fix/ files (overview, safety-model, usage-guide, gitops, check-fix-reference) | L |
| `docs-compliance` | All compliance/ files (overview, cis, mitre, nsa) | M |
| `docs-configuration` | config-file.md, exemptions.md, policies.md | M |
| `docs-integrations` | ci-cd.md, sarif-github.md, ide-integration.md | M |
| `docs-reference` | cli-reference.md, exit-codes.md, environment-variables.md | M |
| `docs-troubleshooting-faq` | faq.md | M |
| `docs-architecture` | architecture/overview.md | M |
| `docs-contributing` | contributing/development.md | M |
| `docs-readme-refactor` | Slim down README.md to point to docs/ | S |
| `docs-cross-reference-validation` | Verify all links, accuracy, completeness | M |

Adjust this list based on what you find in Phase A. Some existing content may reduce effort.

---

## Phase D: Writing

### D1. Execution Strategy

Use **sub-agents** for independent documentation sections. Use **agent teams** when content in one section depends on another (e.g., the check reference pages need consistent formatting established by the overview page).

**Recommended parallelization:**

| Agent | Sections | Dependencies |
|-------|----------|-------------|
| Agent 1 | getting-started/, docs structure, index.md | None — start first, establishes voice and formatting patterns |
| Agent 2 | checks/ (all 12 category pages + overview) | Needs formatting patterns from Agent 1's overview |
| Agent 3 | scanning/, output-formats | Can start after Agent 1 establishes patterns |
| Agent 4 | auto-fix/ (all 5 files) | Independent — references fix code directly |
| Agent 5 | compliance/, configuration/, reference/ | Mostly independent — reads framework and config code |
| Agent 6 | integrations/, troubleshooting/, architecture/, contributing/ | Can start after core docs are drafted |
| Agent 7 | README.md refactor, cross-reference validation | LAST — runs after all other docs exist |

Agent 1 should produce a **style guide snippet** in the first 15 minutes that other agents follow — establishing heading levels, example formatting, cross-reference style, and tone.

### D2. Per-Page Writing Process

For EVERY documentation page:

1. **Read the relevant source code.** Not the spec — the actual implementation. For a check reference page, read every checker's Go file to get the ID, severity, description, and what it actually checks.

2. **Run the commands.** For any page with CLI examples, actually execute them against test fixtures and capture real output. Do not fabricate output.

3. **Write the page.** Follow the three-layer (beginner/practitioner/expert) approach.

4. **Verify accuracy.** Cross-check every flag, every default value, every exit code against the source.

5. **Add cross-references.** Link to related pages. "To learn about filtering by compliance framework, see [Compliance Frameworks](../compliance/overview.md)."

### D3. Check Reference Pages — Special Instructions

The 12 check category pages are the largest deliverable. For each check within a category, include:

```markdown
### check-id-here

**Severity:** High | **Mode:** Live, Manifest | **Auto-Fix:** Safe ✅ / No ❌

What it detects: [one clear sentence]

Why it matters: [one paragraph explaining the security risk in plain language — what could an attacker do?]

**Example of a failing resource:**

​```yaml
# BAD: [explain why]
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: app
    securityContext:
      privileged: true    # ← This is the problem
​```

**How to fix it:**

​```yaml
# GOOD: [explain the fix]
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: app
    securityContext:
      privileged: false
​```

**Auto-fix available:** Yes — Safety: Safe. The fix sets `privileged: false`. This is safe because...
OR
**Auto-fix available:** No — This requires understanding your application's requirements.

**Compliance:** CIS 5.2.1, MITRE T1611, NSA Section 3.1

**Related checks:** [links to related checks]
```

To generate these accurately, for each checker:
1. Read the checker's Go source file to get: ID, severity, description, and the exact field/condition it checks
2. Read the test fixtures in `test/fixtures/<check-id>/` for real passing/failing YAML examples
3. Check the fix registry (`internal/fix/registry.go`) to see if auto-fix is available and at what safety level
4. Check the framework mappings (`internal/frameworks/`) for compliance references

This is the most labor-intensive section. Use sub-agents — one per category or two categories per agent.

### D4. Auto-Fix Documentation — Special Instructions

The auto-fix section must include:

**overview.md:**
- Philosophy: "The safest path should be the easiest path"
- What auto-fix can and cannot do
- Quick example: scan → review diff → apply

**safety-model.md:**
- The five-ring safeguard model explained with real examples for each ring
- Why each ring exists (what failure it prevents)
- How to override each safeguard (and why you should think twice)

**usage-guide.md:**
- Common workflows:
  - "Fix safe issues in my manifests" (the 80% case)
  - "Preview all possible fixes including risky ones"
  - "Fix specific checks only"
  - "Fix and verify"
  - "Fix in CI (non-interactive)"
- Flag combination matrix — which flags work together
- The difference between --output diff/kubectl/helm-values

**gitops-integration.md:**
- Kustomize overlay generation workflow
- Helm values generation workflow
- `--git-pr` workflow (branch, commit, PR)
- Integration with ArgoCD, Flux

**check-fix-reference.md:**
- Table of all 20 auto-fixable checks with: check ID, safety classification, what the fix changes, what could break
- Generated from actual code in `internal/fix/registry.go` and checker FixHint data

### D5. Configuration Documentation — Special Instructions

The configuration reference must be COMPLETE. Read `internal/config/config.go` and document every field:

```yaml
# Full annotated .kubevigil.yaml example
version: "1"

settings:
  severity: medium          # Minimum severity to report
  failOn: high              # Minimum severity for exit code 1
  concurrency: 8            # Max concurrent checks
  includeSystemNamespaces: false
  includeManagedResources: false

checks:
  disabled:                 # Check IDs to skip entirely
    - deprecated-api-usage
  severityOverrides:        # Override default severity
    host-network: critical

exemptions:
  - namespace: monitoring
    kind: DaemonSet
    resource: prometheus-node-exporter
    checks:
      - host-network
      - host-pid
    reason: "Node exporter requires host access for metrics"
    approvedBy: "security-team"
    expires: "2026-06-01"

policies:
  allowedRegistries:
    - gcr.io/my-project
    - docker.io/library

fix:
  additionalSystemNamespaces:
    - my-operator-namespace
  bulkThreshold: 20
  backupDir: /tmp/kubevigil-backups
```

Every field must match the actual Go struct. Read the struct tags to get the YAML field names.

### D6. CI/CD Integration — Special Instructions

Provide complete, working examples for:

**GitHub Actions:**
```yaml
# Complete workflow file that actually works
```

**GitLab CI:**
```yaml
# Complete .gitlab-ci.yml snippet
```

Include: installation step, scan step, SARIF upload step (for GitHub), exit code handling, artifact upload for HTML reports.

### D7. README.md Refactor

After all docs/ content is written, slim the README.md down to:
- Project description (2-3 sentences)
- Badge row (coverage, license, Go version)
- One-liner installation
- 3-5 line quickstart example
- Feature highlights (bullet points, not full documentation)
- Link to full documentation: "📖 [Full Documentation](docs/index.md)"
- Link to check reference
- Link to auto-fix guide
- Contributing section (brief, links to docs/contributing/)
- License

The README should be max ~150-200 lines. It's a landing page, not the documentation. All the deep content moves to docs/.

---

## Phase E: Validation

### E1. Link Verification

```bash
# Find all markdown links and verify targets exist
grep -roh '\[.*\](.*\.md[^)]*)' docs/ | grep -oP '\(.*?\)' | tr -d '()' | sort -u | while read link; do
  # Resolve relative links
  [ -f "docs/$link" ] || echo "BROKEN LINK: $link"
done
```

### E2. Command Verification

Extract every code block with `kubevigil` commands and verify they produce reasonable output:

```bash
grep -rn "kubevigil" docs/ --include="*.md" | grep -E "^\s*(#|kubevigil|\$)" | head -30
```

Spot-check at least 10 command examples by running them against test fixtures.

### E3. Flag Cross-Reference

```bash
# Every flag in --help must appear in docs
go run ./cmd/kubevigil scan --help 2>&1 | grep "^\s*--" | awk '{print $1}' | while read flag; do
  grep -rq "$flag" docs/ || echo "UNDOCUMENTED FLAG: $flag (scan)"
done

go run ./cmd/kubevigil fix --help 2>&1 | grep "^\s*--" | awk '{print $1}' | while read flag; do
  grep -rq "$flag" docs/ || echo "UNDOCUMENTED FLAG: $flag (fix)"
done
```

### E4. Check Completeness

```bash
# Every registered check must appear in a check reference page
go run ./cmd/kubevigil list checks 2>&1 | awk 'NR>2 && NF>0 {print $1}' | while read check; do
  grep -rq "$check" docs/checks/ || echo "UNDOCUMENTED CHECK: $check"
done
```

### E5. Tasks Cleanup

Every issue filed in Phase C must be closed. The cross-reference-validation issue should be the last one closed after all verification passes.

---

## Completion Criteria

- [ ] All documentation files created per the target structure
- [ ] `docs/index.md` exists with complete navigation to every page
- [ ] All 110 checks documented with ID, severity, description, example, remediation
- [ ] All 20 auto-fixable checks documented with safety classification and what changes
- [ ] All CLI flags documented and verified against `--help` output
- [ ] All exit codes documented for both scan and fix commands
- [ ] Complete `.kubevigil.yaml` reference with every field documented
- [ ] CI/CD examples for GitHub Actions and GitLab CI
- [ ] All compliance framework mappings documented
- [ ] Zero broken internal links
- [ ] At least 10 command examples verified by running them
- [ ] README.md refactored to landing page style (~150-200 lines), linking to docs/
- [ ] Tasks clean: all documentation issues closed
- [ ] Git committed and pushed per AGENTS.md protocol

---

## Rules

- **Accuracy over speed.** If you're not sure about a flag's default, read the code. Never guess.
- **Run the binary.** For every command example, actually execute it. Capture real output where possible.
- **Read the source.** For every check description, read the checker's Go file. For every config field, read the struct definition.
- **Working examples.** Every YAML and command example must be syntactically valid and demonstrably correct.
- **Cross-reference generously.** Every page should link to 2-5 related pages. Users navigate docs non-linearly.
- **No duplication.** If content is covered in detail on one page, link to it from other pages rather than repeating it. The one exception: the quickstart can duplicate small snippets for self-containedness.
- **File before writing.** All Tasks issues must be filed before documentation work begins.
- **Use sub-agents aggressively.** The 12 check category pages alone are a massive undertaking. Parallelize.
- **Preserve internal docs.** `docs/internal/kubevigil-features-v3.md`, `docs/internal/testing-strategy.md`, and `docs/internal/prompts/` are internal documents. Do not modify or delete them. They are not user documentation — they are engineering artifacts.
- **Land the plane.** Follow AGENTS.md. Push everything.
