# PROMPT — Release Readiness: CI Hardening, Versioning & Housekeeping

> **Role:** You are a release engineer preparing KubeVigil for its first tagged version. Your mandate is to harden the CI pipeline, establish versioning, create a changelog, normalize the Go version floor, and add dependency vulnerability scanning. No feature work — infrastructure and hygiene only.

---

## Pre-Flight

**Read these files first:**

- `CLAUDE.md` — Project identity, architecture overview
- `AGENTS.md` — Tasks workflow, session completion rules

**Then inspect the current state:**

```bash
# CI pipeline
cat .github/workflows/ci.yml

# Linter config
cat .golangci.yml

# Current Go version references
head -3 go.mod
grep "go-version" .github/workflows/ci.yml
grep "go:" .golangci.yml

# Version metadata
cat internal/version/version.go

# Current README header
head -40 README.md

# Existing tags
git tag -l

# Verify tests pass before any changes
go test ./...
```

**Ground rules:**

- **File Tasks issues before starting work.** One issue per work stream.
- **TDD where applicable.** CI config changes can't be TDD'd locally, but version injection and Go version changes must be verified with `go test ./...` after each change.
- **Coverage must not drop.** Verify at the end: must remain ≥ 93.8%.
- **Do not touch test files** unless a code change requires it.
- **Follow AGENTS.md** for session completion (commit, push).

---

## Work Stream 1: CI Pipeline Hardening

### Tasks Issue

File: `ci-pipeline-hardening` (type: `chore`, priority: P1)

### Current State

The CI pipeline (`.github/workflows/ci.yml`) only runs `go test` and updates a coverage badge. It needs four additions.

### Target CI Pipeline

Restructure `.github/workflows/ci.yml` into this job structure:

```yaml
name: CI

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Run go vet
        run: go vet ./...
      - name: Run golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest

  test:
    name: Test
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Run tests with coverage
        run: go test -race -count=1 -coverprofile=coverage.out ./...
      - name: Check coverage threshold
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Coverage: ${COVERAGE}%"
          # Fail if coverage drops below 90%
          if (( $(echo "$COVERAGE < 90" | bc -l) )); then
            echo "::error::Coverage ${COVERAGE}% is below 90% threshold"
            exit 1
          fi
          echo "percent=$COVERAGE" >> "$GITHUB_OUTPUT"
        id: coverage
      - name: Update coverage badge
        if: github.ref == 'refs/heads/master' && github.event_name == 'push'
        uses: schneegans/dynamic-badges-action@v1.7.0
        with:
          auth: ${{ secrets.GIST_TOKEN }}
          gistID: 1248dd902276859b5cdea636aa5ba175
          filename: kubevigil-coverage.json
          label: coverage
          message: ${{ steps.coverage.outputs.percent }}%
          valColorRange: ${{ steps.coverage.outputs.percent }}
          minColorRange: 0
          maxColorRange: 100

  build:
    name: Build
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Build binary
        run: |
          go build -ldflags "-X github.com/stribog-cloud/kubevigil/internal/version.Version=${{ github.ref_name }} \
                             -X github.com/stribog-cloud/kubevigil/internal/version.Commit=${{ github.sha }} \
                             -X github.com/stribog-cloud/kubevigil/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            -o kubevigil ./cmd/kubevigil
      - name: Verify binary runs
        run: ./kubevigil version

  vulncheck:
    name: Vulnerability Check
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - name: Run govulncheck
        run: govulncheck ./...
```

**Key design decisions:**

- `lint` runs first (fast fail on code quality)
- `test` depends on `lint` (no point testing code that doesn't lint)
- `build` depends on `test` (no point building if tests fail)
- `vulncheck` runs in parallel with `test` (independent, doesn't need test results)
- Coverage threshold at 90% (safety net — current is 93.8%)
- Build step injects version metadata via ldflags
- `golangci-lint-action@v6` uses the existing `.golangci.yml` config automatically

### Verification

You cannot run GitHub Actions locally, but verify:
- The YAML is valid (no syntax errors)
- The `go build` ldflags command works locally:
  ```bash
  go build -ldflags "-X github.com/stribog-cloud/kubevigil/internal/version.Version=v0.3.0 \
                     -X github.com/stribog-cloud/kubevigil/internal/version.Commit=$(git rev-parse HEAD) \
                     -X github.com/stribog-cloud/kubevigil/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /tmp/kubevigil-test ./cmd/kubevigil
  /tmp/kubevigil-test version
  ```
  This must print the version, commit SHA, and build date — not "dev / unknown / unknown".

---

## Work Stream 2: Version Assignment

### Tasks Issue

File: `version-v0.3.0` (type: `chore`, priority: P1)

### What to Do

1. **Do NOT create a git tag yet.** The repo isn't public. We're just setting up the infrastructure so that when a tag IS created, everything works.

2. **Add a Makefile** with build targets that inject version metadata:

```makefile
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MODULE  := github.com/stribog-cloud/kubevigil/internal/version

LDFLAGS := -X $(MODULE).Version=$(VERSION) \
           -X $(MODULE).Commit=$(COMMIT) \
           -X $(MODULE).Date=$(DATE)

.PHONY: build test lint vet clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/kubevigil ./cmd/kubevigil

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vulncheck:
	govulncheck ./...

clean:
	rm -rf bin/ coverage.out
```

3. **Verify the Makefile works:**
```bash
make build
bin/kubevigil version
# Should show: KubeVigil dev (or a commit-based version)
#   Commit: <short SHA>
#   Built:  <timestamp>

make test
make vet
```

4. **Add `bin/` to `.gitignore`** if not already there.

---

## Work Stream 3: CHANGELOG

### Tasks Issue

File: `changelog-initial` (type: `chore`, priority: P2)

### What to Do

Create `CHANGELOG.md` in the project root following [Keep a Changelog](https://keepachangelog.com/) format. This captures everything built across Phases 1-3.

To write an accurate changelog, **read the git log** and the feature docs:

```bash
git log --oneline --all | head -60
cat docs/internal/kubevigil-features-v3.md
```

**Structure:**

```markdown
# Changelog

All notable changes to KubeVigil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Scanning Engine
- Dual-mode scanning: live Kubernetes clusters and static YAML manifests
- Concurrent check execution with configurable parallelism via errgroup
- ResourceCache with Freeze() optimization for zero-allocation List() calls
- Multi-document YAML parsing with directory recursion
- Namespace filtering and resource exemptions via config or annotations

#### Security Checks (110 checks across 12 categories)
- **Workload** (24 checks): container privileges, capabilities, security contexts, ...
  [List all 12 categories with check counts and brief descriptions]

#### Auto-Remediation Engine (Phase 3)
- `kubevigil fix` command with 20 auto-fixable checks
- Comment-preserving YAML patching via AST manipulation
- Five-ring safety model (safe/cautious/moderate/aggressive/force)
- Dry-run mode with unified diff preview
- Backup and restore with timestamped snapshots
- Kustomize overlay generation
- Helm values.yaml generation
- GitOps-compatible output (write patches to directory)
- Fix report generation (text, JSON, Markdown)

#### Compliance Mapping
- CIS Kubernetes Benchmark v1.8
- MITRE ATT&CK for Containers v14
- NSA/CISA Kubernetes Hardening Guide v1.2

#### Output Formats
- Text (colored terminal), JSON, Markdown, HTML, SARIF, YAML, JUnit XML, CSV

#### Configuration
- YAML config file with severity overrides, check enable/disable, exemptions
- Annotation-based per-resource exemptions
- Namespace classification (system vs user)

#### Documentation
- 43 user-facing documentation files covering all features
- Full godoc comments on all 21 packages and exported symbols
- CLI reference with all flags and subcommands

#### CI/CD
- GitHub Actions pipeline with lint, test, build, and vulnerability scanning
- Coverage badge with 90% threshold enforcement
- golangci-lint integration with custom config

#### Performance
- Benchmark suite (39 benchmarks across 5 packages)
- ExtractPodSpecs caching (1,234x faster)
- ResourceCache.List() freeze (zero-allocation reads)
- Single-pass report summary computation
- Flat-table LCS diff algorithm
- End-to-end scan: 42-51% faster, 61-65% less memory vs initial implementation
```

**Important:**
- Read the actual git history and feature docs to get the details right. The above is a skeleton — fill in specifics for each checker category, each output format, etc.
- Do NOT fabricate features. Verify each claim against the code.
- Keep descriptions concise — one line per feature, grouped logically.
- Everything goes under `[Unreleased]` since we haven't tagged v0.3.0 yet. When the tag is created later, this section gets renamed to `[0.3.0] - <date>`.

---

## Work Stream 4: Go Version Normalization

### Tasks Issue

File: `go-version-normalize` (type: `chore`, priority: P2)

### Analysis

KubeVigil's actual minimum Go version is **1.22** based on:
- `log/slog` — Go 1.21+
- `slices` package — Go 1.21+
- Generics (`sortedKeys[T any]`) — Go 1.18+
- No range-over-int (1.22) or range-over-func (1.23) features used
- Go 1.22 chosen as floor because it is the oldest currently-supported Go release and matches CI

The `go.mod` currently says `go 1.25.0` which is too restrictive.

### What to Do

1. **Update `go.mod`:**
   ```bash
   go mod edit -go=1.22.0
   go mod tidy
   ```

2. **Verify build and tests still work:**
   ```bash
   go build ./...
   go test ./...
   ```

3. **Update all references for consistency:**

   | File | Current | Target |
   |------|---------|--------|
   | `go.mod` | `go 1.25.0` | `go 1.22.0` |
   | `.github/workflows/ci.yml` | `go-version: '1.22'` | `go-version: '1.22'` (already correct) |
   | `.golangci.yml` | `go: "1.22"` | `go: "1.22"` (already correct) |
   | `README.md` | Check if Go version mentioned | Update if present |
   | `docs/getting-started/installation.md` | Check if Go version mentioned | Update if present |
   | `docs/contributing/guide.md` | Check if Go version mentioned | Update if present |

4. **Search for any other Go version references:**
   ```bash
   grep -rn "1\.25\|1\.24\|1\.23\|go 1\." --include="*.md" --include="*.yml" --include="*.yaml" --include="*.mod" .
   ```
   Update all to consistently say Go 1.22+.

5. **After `go mod tidy`, check if `go.sum` changed.** If so, commit it.

### Verification

```bash
go build ./...
go test ./...
go vet ./...
head -3 go.mod  # Must say go 1.22.0 (or go 1.22)
```

---

## Work Stream 5: Dependency Vulnerability Scanning

### Tasks Issue

File: `govulncheck-setup` (type: `chore`, priority: P2)

### What to Do

1. **Install govulncheck locally and run it:**
   ```bash
   go install golang.org/x/vuln/cmd/govulncheck@latest
   govulncheck ./...
   ```

2. **If vulnerabilities are found:**
   - Document each finding (module, CVE, affected function)
   - Attempt to update the vulnerable dependency: `go get <module>@latest`
   - Run `go mod tidy`
   - Run `go test ./...` — if tests pass, keep the update
   - If tests fail after update, revert and document the vulnerability as a known issue
   - **Do NOT force-update a dependency that breaks tests**

3. **If no vulnerabilities found:** Record a clean bill of health in the commit message.

4. **CI integration is handled in Work Stream 1** (the `vulncheck` job). No additional work needed here — just ensure the local run succeeds.

### Verification

```bash
govulncheck ./...
# Must either pass clean or have documented exceptions
go test ./...
# Must still pass
```

---

## Parallelization

| Agent | Work Stream | Dependencies |
|-------|-------------|-------------|
| Agent 1 | WS4: Go version normalization | None — start first (other streams depend on correct go.mod) |
| Agent 2 | WS5: govulncheck + dependency updates | After WS4 (go mod tidy may change deps) |
| Agent 3 | WS1: CI pipeline hardening | After WS4 (CI go-version must match) |
| Agent 4 | WS2: Makefile + version infrastructure | After WS4 |
| Agent 5 | WS3: CHANGELOG | Independent — can run in parallel with all others |
| Agent 6 | Final verification | LAST — runs after all others complete |

**Agent teams:**
- WS1 + WS2 share the ldflags build pattern — coordinate to avoid conflicts in how version is injected.
- WS4 + WS5 are sequential (version change first, then vuln scan with updated deps).

---

## Final Verification

After all work streams complete:

```bash
# 1. All tests pass
go test ./...

# 2. Linting clean
go vet ./...
golangci-lint run ./...

# 3. Coverage not dropped
go test -coverprofile=/tmp/kv-release.out ./...
go tool cover -func=/tmp/kv-release.out | tail -1
# Must be ≥ 93.8%

# 4. Build with version injection works
make build
bin/kubevigil version
# Must show version, commit, date — not "dev / unknown / unknown"

# 5. Go version normalized
head -3 go.mod
# Must say go 1.22.0 or go 1.22

# 6. No untracked files that should be ignored
git status --porcelain

# 7. govulncheck clean (or documented exceptions)
govulncheck ./...

# 8. CHANGELOG exists and is non-empty
wc -l CHANGELOG.md

# 9. CI YAML is valid
# (Can't validate locally, but check no syntax errors)
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" 2>/dev/null || echo "Install PyYAML to validate, or just eyeball it"

# 10. Makefile targets work
make test
make vet
make clean
```

---

## Completion Criteria

- [ ] CI pipeline has 4 jobs: lint, test (with 90% threshold), build (with ldflags), vulncheck
- [ ] Makefile with build/test/lint/vet/cover/vulncheck/clean targets
- [ ] `make build && bin/kubevigil version` shows real version metadata
- [ ] CHANGELOG.md with complete Phase 1-3 feature inventory under `[Unreleased]`
- [ ] `go.mod` says `go 1.22.0` (or `go 1.22`)
- [ ] All Go version references consistent across go.mod, CI, golangci.yml, docs
- [ ] `govulncheck ./...` passes (or vulnerabilities documented)
- [ ] `go test ./...` — all 23 packages pass
- [ ] `go vet ./...` — clean
- [ ] Coverage ≥ 93.8%
- [ ] `bin/` in `.gitignore`
- [ ] All Tasks issues closed
- [ ] Git committed and pushed per AGENTS.md

---

## Rules

- **File before fixing.** All Tasks issues filed before work begins.
- **Verify after every change.** Run `go test ./...` after each work stream, not just at the end.
- **Do not change application logic.** This is infrastructure work. The scanning engine, checkers, fix engine, and report generators must not be modified.
- **Do not create git tags.** The repo is private. Version infrastructure is set up for future tagging, but no tags are created now.
- **Do not add Docker/release tooling.** No Dockerfile, no GoReleaser, no brew formula. That's future work.
- **CHANGELOG must be accurate.** Read the code and git history. Do not fabricate features or check counts. Verify against `register.go` files for checker counts.
- **Dependency updates are conservative.** Only update if govulncheck flags a vulnerability AND tests pass after the update. Do not speculatively update deps.
- **Coverage is a floor.** 93.8% must not drop. Infrastructure changes shouldn't affect it, but verify.
