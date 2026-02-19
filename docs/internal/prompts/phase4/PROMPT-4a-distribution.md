# PROMPT — Phase 4a: Distribution & Binary Releases

> **Role:** You are a release engineer. Your job is to make KubeVigil installable in under 30 seconds on any platform, with zero Go toolchain dependency. You will set up GoReleaser for cross-platform binaries, a GitHub Actions release workflow, a Dockerfile, an install script, and update the README with real installation instructions.

---

## Pre-Flight

**Read these files first:**

- `CLAUDE.md` — Project identity, architecture, coding standards
- `AGENTS.md` — Tasks workflow, session completion rules (push is MANDATORY)
- `Makefile` — Existing build infrastructure (ldflags pattern, targets)
- `.github/workflows/ci.yml` — Existing CI workflow (do NOT modify)
- `internal/version/version.go` — Version injection points (Version, Commit, Date)
- `README.md` — Current Quick Start section (will be rewritten)

**Verify baseline before ANY changes:**

```bash
go test ./... -count=1
go vet ./...
make build && bin/kubevigil version
```

**Ground rules:**

- **File Tasks issues before starting work.** One issue per deliverable (GoReleaser, release workflow, Dockerfile, install script, README, Homebrew, Krew).
- **Do NOT modify .github/workflows/ci.yml.** The existing CI pipeline is stable and must not change.
- **Do NOT modify any Go source code** unless strictly necessary (e.g., adding a `--version` JSON flag). The distribution layer wraps the existing binary — it does not change it.
- **Do NOT modify any existing tests.** Coverage must remain ≥ 93.8%.
- **Test every artifact locally** before committing. GoReleaser has `--snapshot`, Docker has `docker build`, scripts can be tested in `/tmp`.
- **Follow AGENTS.md** for session completion (commit, push, verify CI).

---

## Current State

| What Exists | Details |
|-------------|---------|
| Makefile | `make build` with ldflags injecting Version, Commit, Date |
| CI workflow | 4 jobs: lint, test, build, vulncheck (on push to master + PRs) |
| Version injection | `internal/version/version.go` — 3 vars set via `-ldflags -X` |
| Git tag | `v0.3.0` exists, points to latest master |
| GitHub Releases | Empty — no releases created yet |
| Installation | `go install` only — requires Go toolchain |
| Docker | None |
| Homebrew | None |
| Krew | None |

---

## Deliverables

### 1. GoReleaser Configuration (`.goreleaser.yaml`)

Create `.goreleaser.yaml` at the repo root.

**Requirements:**

- **Project name:** `kubevigil`
- **Build:** Single binary from `./cmd/kubevigil`
- **Platforms:** Linux (amd64, arm64), macOS (amd64, arm64), Windows (amd64)
  - That's 5 targets. No 32-bit, no exotic architectures.
- **ldflags:** Must match the existing Makefile pattern exactly:
  ```
  -X github.com/stribog-cloud/kubevigil/internal/version.Version={{.Version}}
  -X github.com/stribog-cloud/kubevigil/internal/version.Commit={{.ShortCommit}}
  -X github.com/stribog-cloud/kubevigil/internal/version.Date={{.Date}}
  ```
- **Archives:** tar.gz for Linux/macOS, zip for Windows. Include `LICENSE`, `README.md`, `CHANGELOG.md` in each archive.
- **Checksum:** SHA256 checksums file (`kubevigil_checksums.txt`)
- **Release notes:** Auto-generate from CHANGELOG.md (use `changelog.use: github-native` or extract from CHANGELOG)
- **Snapshot:** Must work with `goreleaser release --snapshot --clean` for local testing
- **No CGO:** Set `CGO_ENABLED=0` for static binaries
- **Strip debug info:** Add `-s -w` to ldflags for smaller binaries

**Verification:**

```bash
# Install goreleaser locally if needed
brew install goreleaser  # or: go install github.com/goreleaser/goreleaser/v2@latest

# Test the config
goreleaser check

# Build snapshot (no publish)
goreleaser release --snapshot --clean

# Verify artifacts exist
ls dist/kubevigil_linux_amd64_v1/kubevigil
ls dist/kubevigil_darwin_arm64/kubevigil
ls dist/kubevigil_windows_amd64_v1/kubevigil.exe
file dist/kubevigil_linux_amd64_v1/kubevigil  # should say "statically linked"
```

**Tasks issue:** `goreleaser-config` (type: `task`, priority: P1)

---

### 2. GitHub Actions Release Workflow (`.github/workflows/release.yml`)

Create a NEW workflow file. Do NOT modify `ci.yml`.

**Trigger:** Only on tag push matching `v*`:

```yaml
on:
  push:
    tags:
      - 'v*'
```

**Jobs:**

1. **test** — Run full test suite first (same as CI: `go test -race -count=1 ./...`). Release must not proceed if tests fail.
2. **release** — Run GoReleaser with `GITHUB_TOKEN` to create the GitHub Release and upload artifacts.

**Requirements:**

- Uses `goreleaser/goreleaser-action@v6` (or latest stable)
- `GITHUB_TOKEN` has `contents: write` permission (for creating releases)
- GoReleaser version pinned (use same version as local install)
- The test job runs BEFORE the release job (`needs: test`)
- Uses `actions/setup-go@v5` with `go-version: '1.25'`
- Uses `actions/checkout@v4` with `fetch-depth: 0` (GoReleaser needs full git history for changelog)

**Important:** This workflow creates a GitHub Release with:
- Pre-built binaries for all 5 platforms
- SHA256 checksums
- Auto-generated release notes

**Verification:**

After pushing the workflow, test with a pre-release tag:

```bash
# Do NOT create a real release yet — use the workflow file check
# The workflow will be tested when we tag v0.4.0 (or a test tag like v0.3.1-rc1)
# For now, verify the YAML is syntactically valid and the job graph is correct.
```

**Tasks issue:** `release-workflow` (type: `task`, priority: P1)

---

### 3. Dockerfile

Create `Dockerfile` at the repo root.

**Requirements:**

- **Multi-stage build:**
  - Stage 1 (`builder`): `golang:1.25` base, copy source, build with ldflags (same as Makefile)
  - Stage 2 (`runtime`): `gcr.io/distroless/static-debian12` (or `scratch` + CA certificates)
  - Copy only the binary from builder to runtime
- **CGO_ENABLED=0** for static linking
- **Labels:** OCI labels for image metadata (org.opencontainers.image.*)
- **User:** Run as non-root (UID 65532 for distroless, or set USER in scratch)
- **Entrypoint:** `["/kubevigil"]` — no shell wrapping
- **ARG for version:** Accept VERSION, COMMIT, DATE as build args for ldflags

**Must NOT include:**
- Go toolchain in the final image
- Source code in the final image
- Anything except the binary, CA certs, and timezone data

**Verification:**

```bash
# Build
docker build -t kubevigil:test \
  --build-arg VERSION=v0.3.0 \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  .

# Verify it works
docker run --rm kubevigil:test version

# Verify image is small (should be < 30MB)
docker images kubevigil:test

# Verify no Go toolchain leaked
docker run --rm --entrypoint="" kubevigil:test ls /usr/local/go 2>&1 | grep -i "no such" && echo "OK: no Go in image"
```

**Tasks issue:** `dockerfile` (type: `task`, priority: P1)

---

### 4. Install Script (`install.sh`)

Create `install.sh` at the repo root.

**Requirements:**

- Detects OS (Linux, macOS, Windows via WSL) and architecture (amd64, arm64)
- Downloads the correct binary from the latest GitHub Release
- Verifies SHA256 checksum against the checksums file
- Installs to `/usr/local/bin` (or `$HOME/.local/bin` if no root access)
- Works with both `curl` and `wget`
- Prints version after install to confirm success
- Supports `KUBEVIGIL_INSTALL_DIR` env var for custom install location
- Has `set -euo pipefail` and proper error handling

**Must NOT:**
- Require Go, Node, Python, or any runtime
- Silently fail — every error must produce a clear message

**Usage pattern:**

```bash
# One-liner install
curl -sSL https://raw.githubusercontent.com/msambare/KubeVigil/master/install.sh | bash

# Or download and inspect first
curl -sSL -o install.sh https://raw.githubusercontent.com/msambare/KubeVigil/master/install.sh
less install.sh
bash install.sh
```

**Verification:**

```bash
# Syntax check
bash -n install.sh

# Test the detection logic locally
bash install.sh --help 2>&1 || true
```

**Tasks issue:** `install-script` (type: `task`, priority: P2)

---

### 5. README Installation Section

**Rewrite the Quick Start section** to show multiple installation methods.

**New structure (replace the current "## Quick Start" section):**

Add a new `## Installation` section BEFORE `## Quick Start`. Move the `go install` line from Quick Start into the Installation section as the last option ("From Source").

Keep the existing Quick Start usage examples (scan manifests, scan live, filter severity, HTML output, fix preview) under `## Quick Start` — but remove the `# Install` line from it since that's now in the Installation section.

**Installation methods in order:**
1. Homebrew (macOS / Linux)
2. Krew (kubectl plugin)
3. Binary install script
4. Download from GitHub Releases (manual)
5. Docker
6. From Source (`go install`)

**Requirements:**
- Each method is exactly one command (copy-paste friendly)
- Docker examples show volume mounts for manifests and kubeconfig
- Link to GitHub Releases for manual download
- Keep concise — no prose paragraphs between install commands

**Tasks issue:** `readme-installation` (type: `task`, priority: P1)

---

### 6. Homebrew Tap

**Approach:** Use GoReleaser's built-in Homebrew tap support.

Add a `brews` section to `.goreleaser.yaml`.

**⚠️ IMPORTANT — Private repo gating:** The repo is currently **private**. Homebrew tap auto-push requires the binary download URLs to be publicly accessible. Therefore:
1. Add the `brews` config to `.goreleaser.yaml` but **commented out** with a clear note: `# Uncomment when repo is made public`
2. Create a standalone template formula at `deploy/homebrew/kubevigil.rb` as a reference
3. File a Tasks issue for enabling it when the repo goes public (leave issue OPEN, do not close)

**Tasks issue:** `homebrew-tap` (type: `task`, priority: P2, **leave OPEN — blocked on public repo**)

---

### 7. Krew Plugin Manifest

Create `deploy/krew/kubevigil.yaml` — a Krew plugin manifest.

**Requirements:**

- Plugin name: `vigil` (command becomes `kubectl vigil`)
- Description matches README tagline
- Platforms: Linux (amd64, arm64), macOS (amd64, arm64), Windows (amd64)
- Download URLs point to GitHub Releases archives
- SHA256 checksums for each platform (use placeholders — updated at release time)

**⚠️ IMPORTANT — Private repo gating:** Same as Homebrew. Krew index submission requires a public repo:
1. Create the manifest file now for testing and reference
2. File a Tasks issue for Krew index submission when repo goes public (leave issue OPEN, do not close)

**Verification:**

```bash
# Local testing (after GoReleaser snapshot)
kubectl krew install --manifest=deploy/krew/kubevigil.yaml --archive=dist/kubevigil_linux_amd64.tar.gz
kubectl vigil version
```

**Tasks issue:** `krew-manifest` (type: `task`, priority: P2, **leave OPEN — blocked on public repo**)

---

### 8. .dockerignore

Create `.dockerignore` to keep the Docker build context small and prevent leaking secrets.

```
.git
bin/
dist/
coverage.out
*.out
test/
docs/
.github/
.golangci.yml
```

No separate Tasks issue needed — bundle with the Dockerfile issue.

---

## Parallelization

| Agent | Deliverable(s) | Dependencies |
|-------|----------------|--------------|
| Agent 1 | GoReleaser config + snapshot test | None |
| Agent 2 | Release workflow | Needs GoReleaser config (Agent 1) |
| Agent 3 | Dockerfile + .dockerignore | None |
| Agent 4 | Install script | Needs GoReleaser config (for archive naming convention) |
| Agent 5 | README rewrite | Needs all other agents' output (names, paths, commands) |
| Agent 6 | Homebrew + Krew manifests | Needs GoReleaser config (Agent 1) |

**Recommended order if sequential:**
1. GoReleaser config → snapshot test
2. Dockerfile + .dockerignore → docker build test
3. Release workflow
4. Install script
5. Homebrew + Krew manifests
6. README rewrite (last — references everything else)

---

## Verification Checklist

After all deliverables are complete:

```bash
# 1. Existing tests still pass (no Go code changed, but verify anyway)
go test ./... -count=1
go vet ./...

# 2. Coverage unchanged
go test -coverprofile=/tmp/kv-dist.out ./...
go tool cover -func=/tmp/kv-dist.out | tail -1
# Must be ≥ 93.8%

# 3. GoReleaser config valid
goreleaser check

# 4. GoReleaser snapshot builds
goreleaser release --snapshot --clean

# 5. All 5 platform binaries exist and are static
file dist/kubevigil_linux_amd64_v1/kubevigil
file dist/kubevigil_darwin_arm64/kubevigil

# 6. Docker image builds and runs
docker build -t kubevigil:test .
docker run --rm kubevigil:test version
docker images kubevigil:test --format '{{.Size}}'  # should be < 30MB

# 7. Install script syntax is valid
bash -n install.sh

# 8. Existing CI workflow untouched
git diff .github/workflows/ci.yml  # must be empty

# 9. README has all installation methods
grep -c "brew install\|krew install\|docker run\|curl.*install.sh\|go install" README.md
# Should be ≥ 5 (one per method)

# 10. All new files committed
git status  # no untracked distribution files
```

---

## Completion Criteria

- [ ] `.goreleaser.yaml` — valid config, snapshot builds 5 platform binaries
- [ ] `.github/workflows/release.yml` — triggers on `v*` tags, runs tests then GoReleaser
- [ ] `Dockerfile` — multi-stage, distroless/scratch runtime, < 30MB image, non-root
- [ ] `.dockerignore` — excludes .git, dist, test, docs
- [ ] `install.sh` — detects OS/arch, downloads binary, verifies checksum, installs
- [ ] `deploy/homebrew/kubevigil.rb` — formula template (commented in goreleaser until repo is public)
- [ ] `deploy/krew/kubevigil.yaml` — plugin manifest for `kubectl vigil`
- [ ] `README.md` — Installation section with 6 methods, usage examples preserved
- [ ] All Tasks issues filed (close completed ones, leave Homebrew + Krew OPEN as blocked)
- [ ] Existing tests pass (`go test ./...`)
- [ ] Coverage ≥ 93.8%
- [ ] Existing CI workflow (`ci.yml`) NOT modified
- [ ] No Go source code modified (unless strictly necessary with justification)
- [ ] GoReleaser snapshot tested locally
- [ ] Docker image built and tested locally
- [ ] Git committed and pushed per AGENTS.md
- [ ] CI passes

---

## Rules

- **File before building.** All Tasks issues filed before any work starts.
- **Do NOT modify ci.yml.** The existing CI pipeline is stable.
- **Do NOT modify Go source code** unless absolutely necessary (document why if you do).
- **Test every artifact locally.** GoReleaser snapshot, Docker build, install script syntax.
- **Static binaries only.** CGO_ENABLED=0 everywhere. No dynamic linking.
- **Minimal Docker image.** Distroless or scratch. No Ubuntu, no Alpine, no Go toolchain in final image.
- **Checksum verification.** Install script MUST verify SHA256. No trust-on-download.
- **Private repo awareness.** The repo is currently private. Homebrew tap auto-push and Krew index submission require a public repo. Create the configs/manifests now but gate publishing behind repo visibility. Document this clearly with comments in the files.
- **README is the storefront.** The installation section is the first thing potential users see. Every method should be a single copy-paste command.
- **ldflags must match.** GoReleaser, Dockerfile, and Makefile must inject the same three version variables with the same module path. Any mismatch means `kubevigil version` shows wrong info on some platforms.
- **Release workflow must not run on ci.yml triggers.** Tag pushes only. Pushing to master must NOT create a release.
- **Preserve existing Makefile.** Developers who prefer `make build` should still work. GoReleaser is for releases; Make is for development.
- **dist/ must be gitignored.** GoReleaser snapshot creates a `dist/` directory. Add it to `.gitignore` if not already there.
- **Context window management.** This prompt has no Go code changes. Focus on configuration files, shell scripts, and documentation. Do not read the entire Go codebase — you only need `version.go` and the Makefile.
