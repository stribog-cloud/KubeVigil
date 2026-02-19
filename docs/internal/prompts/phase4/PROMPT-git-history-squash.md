# PROMPT — Git History Squash: 148 Commits → 5 Phase Commits

> **Role:** You are performing a precise git history rewrite on a private repository. The goal is to replace 148 granular commits with exactly 5 clean, phase-based commits while preserving the exact final code state. This is a destructive operation — follow every step exactly, verify at every checkpoint, and do NOT skip any verification.

---

## Overview

**Repository:** `/Users/msambare/code/KubeVigil`
**Remote:** `https://github.com/msambare/KubeVigil.git`
**Current state:** 148 commits on `master`, tag `v0.3.0` at commit `f1c84be`
**Target state:** 5 commits on `master`, tag `v0.3.0` on the final (5th) commit

The 5 commits represent the tree state at each major milestone. The final commit's tree will be **bit-for-bit identical** to the current HEAD. No code changes — this is purely a history rewrite.

---

## CRITICAL: Read Before Starting

1. **Working directory must be clean.** Run `git status` — if there are ANY uncommitted changes, STOP and ask the user.
2. **You must be on the `master` branch.** Run `git branch` — if not on master, STOP.
3. **No other local branches should exist.** This simplifies the operation.
4. **Internet access required.** You will push to GitHub multiple times.
5. **Do NOT use `git filter-branch`, `git rebase -i`, or any interactive commands.** This prompt uses the orphan branch approach, which is deterministic and non-interactive.

---

## Phase Boundary Map

These are the exact commits whose **tree state** (file contents) will be captured in each squashed commit:

| Squashed Commit | Tree Source (SHA) | Original Message | Files |
|----------------|-------------------|------------------|-------|
| 1. Phase 1 — Foundation | `ca581d5` | `feat: complete Phase 1 — CLI, integration tests, and README` | 197 |
| 2. Phase 2 — Full Scanner | `1bba59c` | `perf: reduce HTML report size ~74% via dedup, columnar JSON, lazy render` | 625 |
| 3. CI & Testing Infrastructure | `e4e7601` | `docs: remove Tasks section from E2E report, fix cross-validation numbers` | 730 |
| 4. Phase 3 — Auto-Remediation | `0166035` | `chore: add .claude/ to .gitignore` | 831 |
| 5. Hardening & Release Prep | `7759cda` (current HEAD) | `docs: restructure roadmap phases 4-9 (distribution before CI/CD)` | 860 |

---

## Step-by-Step Procedure

### Step 0: Pre-flight Verification

Run ALL of these. If any check fails, STOP and report.

```bash
cd /Users/msambare/code/KubeVigil

# 0a. Clean working directory
git status --short
# MUST be empty. If not, STOP.

# 0b. On master branch
git branch --show-current
# MUST say "master"

# 0c. In sync with remote
git fetch origin
git diff master origin/master --stat
# MUST show no differences

# 0d. Record current HEAD (this is your ground truth)
ORIGINAL_HEAD=$(git rev-parse HEAD)
echo "Original HEAD: $ORIGINAL_HEAD"
# MUST be: 7759cda18d849073bee28dc2e48b1bd3eef02164

# 0e. Record current tree hash (this is what we verify against at the end)
ORIGINAL_TREE=$(git rev-parse HEAD^{tree})
echo "Original tree: $ORIGINAL_TREE"

# 0f. Record file count
git ls-tree -r HEAD --name-only | wc -l
# MUST be 860

# 0g. Verify boundary commits exist
git cat-file -t ca581d5  # commit
git cat-file -t 1bba59c  # commit
git cat-file -t e4e7601  # commit
git cat-file -t 0166035  # commit
git cat-file -t 7759cda  # commit
```

**Save the `ORIGINAL_TREE` value.** You will use it in Step 6 to verify the final result.

---

### Step 1: Create Safety Backup

Push the current history to a backup branch on the remote. This is your safety net — if anything goes wrong, you can restore from this.

```bash
# Create backup branch from current master
git branch pre-squash-backup master

# Push backup to remote
git push origin pre-squash-backup

# Verify backup exists on remote
git branch -r | grep pre-squash-backup
# MUST show: origin/pre-squash-backup
```

**CHECKPOINT:** Verify the backup is on GitHub before proceeding. Run:
```bash
git log --oneline origin/pre-squash-backup | wc -l
# MUST be 148
```

---

### Step 2: Create Orphan Branch with 5 Commits

This creates a new branch with no history, then builds exactly 5 commits by reading the tree state at each phase boundary.

```bash
# Switch to a new orphan branch (no parent commits)
git checkout --orphan squashed-history

# Remove everything from the index (orphan branches start with all files staged)
git rm -rf . > /dev/null 2>&1

# --- COMMIT 1: Phase 1 Foundation ---
# Read the entire tree from the Phase 1 boundary commit
git read-tree ca581d5^{tree}
git checkout -- .
git add -A
git commit -m "feat: Phase 1 — core engine, 25 workload checks, CLI, text/JSON output

Core scanning engine with live cluster and manifest modes.
25 workload security checkers (run-as-root, privileged, host-namespace, etc).
Configuration system with namespace exemptions.
Text and JSON report output.
Cobra CLI: scan, list, version commands.
Table-driven tests with 15+ cases per checker.
Contract tests for interface compliance.

Covers original commits: ee4943f..ca581d5"

# --- COMMIT 2: Phase 2 Full Scanner ---
# Clear working tree and read Phase 2 tree
git rm -rf . > /dev/null 2>&1
git read-tree 1bba59c^{tree}
git checkout -- .
git add -A
git commit -m "feat: Phase 2 — 110 checks, 8 output formats, compliance frameworks, HTML report

85 additional security checks across 12 categories (110 total):
  image, RBAC, secrets, network, PSA, scheduling, storage,
  cluster config, supply chain, cloud provider, CRD.
8 output formats: text, JSON, YAML, Markdown, HTML, SARIF, JUnit, CSV.
3 compliance framework mappings: CIS v1.8, MITRE ATT&CK v14, NSA/CISA v1.2.
Executive summary with posture scoring.
Professional HTML report with dark mode, interactive dashboard, SVG charts.
Namespace tier classification (Application / Infrastructure / Cluster-Scoped).
YAML remediation snippets for all 110 checkers.
Live cluster bug fixes and severity calibration.

Covers original commits: 54a9f02..1bba59c"

# --- COMMIT 3: CI & Testing Infrastructure ---
git rm -rf . > /dev/null 2>&1
git read-tree e4e7601^{tree}
git checkout -- .
git add -A
git commit -m "ci: GitHub Actions pipeline, E2E testing, coverage infrastructure

GitHub Actions CI: lint (golangci-lint), test (with coverage threshold),
  build (ldflags version injection), vulnerability check (govulncheck).
Dynamic coverage badge via GitHub Gist.
E2E testing with Kind clusters (11 scan scenarios).
Bats test framework integration.
Coverage improvements to 90%+.
TDD regression tests for 6 production bug fixes.
Multi-cluster validation and cross-tool comparison.

Covers original commits: 31c1612..e4e7601"

# --- COMMIT 4: Phase 3 Auto-Remediation ---
git rm -rf . > /dev/null 2>&1
git read-tree 0166035^{tree}
git checkout -- .
git add -A
git commit -m "feat: Phase 3 — auto-remediation engine, 20 fixable checks, safety model

kubevigil fix command: scan manifests, identify fixable findings, generate patches.
YAML round-trip editing via yaml.v3 Node API (preserves comments/formatting).
20 auto-fixable checks with FixHint backfill.
Five-ring safeguard model:
  1. Dry-run by default
  2. Fix safety classification (safe/likely-safe/potentially-breaking/manual-only)
  3. System namespace hard block
  4. Interactive bulk confirmation
  5. Mandatory backup with RESTORE.md
Output generators: Kustomize overlays, Helm values, kubectl patches, GitOps PRs.
9 E2E fix scenarios with 18 Bats tests.
Comprehensive user documentation (47 files).
Coverage: 93.8%.

Covers original commits: 844a219..0166035"

# --- COMMIT 5: Hardening & Release Prep ---
git rm -rf . > /dev/null 2>&1
git read-tree 7759cda^{tree}
git checkout -- .
git add -A
git commit -m "chore: hardening — perf audit, godoc, CI fixes, report parity, v0.3.0

Performance audit: 42-51% faster scanning, 61-65% less memory.
39 benchmarks across hot paths.
Godoc comments on all 21 packages and exported symbols.
CI hardening: golangci-lint v2.10.1, Go 1.25 normalization.
Report format audit: all 7 non-HTML formats updated for data parity.
  Text: tier grouping, compliance summary, top risks.
  JSON/YAML: check aggregates, passed checks, tier breakdown, posture scores.
  Markdown: top risks, per-tier scores.
  CSV: metadata header, auto-fixable/current/desired columns.
  SARIF: rule descriptions, remediation, help URIs.
  JUnit: passed test cases, timestamps, descriptive suite names.
Roadmap restructured: Phases 4-9 (distribution before CI/CD).
CHANGELOG.md linked from README.
Coverage: 93.9%.

Covers original commits: 418e5fc..7759cda"
```

---

### Step 3: Verify the Squashed Branch

This is the most important verification. The tree of the final commit on `squashed-history` MUST be identical to the tree of the original `master`.

```bash
# 3a. Verify we have exactly 5 commits
git log --oneline squashed-history | wc -l
# MUST be exactly 5

# 3b. Verify the final tree matches the original master tree
SQUASHED_TREE=$(git rev-parse squashed-history^{tree})
echo "Squashed tree: $SQUASHED_TREE"
echo "Original tree: $ORIGINAL_TREE"
# These two values MUST be identical

if [ "$SQUASHED_TREE" = "$ORIGINAL_TREE" ]; then
    echo "✅ TREE MATCH — safe to proceed"
else
    echo "❌ TREE MISMATCH — DO NOT PROCEED"
    echo "Something went wrong. Investigate before continuing."
    # STOP HERE if this fails
fi

# 3c. Double-check with diff (belt AND suspenders)
git diff squashed-history master --stat
# MUST show no differences (empty output)

# 3d. Verify file count matches
git ls-tree -r squashed-history --name-only | wc -l
# MUST be 860

# 3e. Verify intermediate trees are correct too
echo "Phase 1 files:" && git ls-tree -r squashed-history~4 --name-only | wc -l  # Should be 197
echo "Phase 2 files:" && git ls-tree -r squashed-history~3 --name-only | wc -l  # Should be 625
echo "Phase 3 files:" && git ls-tree -r squashed-history~2 --name-only | wc -l  # Should be 730
echo "Phase 4 files:" && git ls-tree -r squashed-history~1 --name-only | wc -l  # Should be 831
echo "Phase 5 files:" && git ls-tree -r squashed-history --name-only | wc -l    # Should be 860
```

**If ANY check in Step 3 fails, STOP. Do NOT continue to Step 4. Report the failure.**

---

### Step 4: Replace Master

Only proceed if Step 3 passed all checks.

```bash
# Switch to master
git checkout master

# Point master to the squashed branch
git reset --hard squashed-history

# Delete the temporary branch name (master now IS the squashed history)
git branch -d squashed-history

# Verify master has exactly 5 commits
git log --oneline | wc -l
# MUST be 5

# Verify the tree is still correct
FINAL_TREE=$(git rev-parse HEAD^{tree})
if [ "$FINAL_TREE" = "$ORIGINAL_TREE" ]; then
    echo "✅ Master tree matches original — ready to push"
else
    echo "❌ MISMATCH — restoring from backup"
    git reset --hard pre-squash-backup
    # STOP HERE
fi
```

---

### Step 5: Update Tag and Force-Push

```bash
# 5a. Delete the old v0.3.0 tag (locally and on remote)
git tag -d v0.3.0
git push origin --delete v0.3.0

# 5b. Create new v0.3.0 tag on the final (5th) commit
git tag v0.3.0 HEAD

# 5c. Force-push master (this replaces the 148-commit history with 5 commits)
git push --force origin master

# 5d. Push the new tag
git push origin v0.3.0

# 5e. Verify remote state
echo "=== Remote master ==="
git log --oneline origin/master
# MUST show exactly 5 commits

echo "=== Remote tags ==="
git ls-remote --tags origin
# MUST show v0.3.0

echo "=== Remote backup ==="
git log --oneline origin/pre-squash-backup | wc -l
# MUST still be 148 (safety net intact)
```

---

### Step 6: Full Verification

Run every check. ALL must pass.

```bash
echo "=== 6a. Commit count ==="
git log --oneline | wc -l
# MUST be 5

echo "=== 6b. Tree integrity ==="
VERIFY_TREE=$(git rev-parse HEAD^{tree})
if [ "$VERIFY_TREE" = "$ORIGINAL_TREE" ]; then
    echo "✅ Tree hash matches original"
else
    echo "❌ CRITICAL: Tree mismatch after push"
fi

echo "=== 6c. File count ==="
git ls-tree -r HEAD --name-only | wc -l
# MUST be 860

echo "=== 6d. Tag points to HEAD ==="
git rev-parse v0.3.0
git rev-parse HEAD
# Both MUST be the same SHA

echo "=== 6e. Tests pass ==="
go test ./... -count=1
# ALL 23 packages MUST pass

echo "=== 6f. go vet ==="
go vet ./...
# MUST be clean

echo "=== 6g. Build works ==="
make build
bin/kubevigil version
# MUST show v0.3.0

echo "=== 6h. Coverage intact ==="
go test -coverprofile=/tmp/kv-squash-verify.out ./...
go tool cover -func=/tmp/kv-squash-verify.out | tail -1
# MUST be ≥ 93.8%

echo "=== 6i. Remote in sync ==="
git diff master origin/master --stat
# MUST be empty

echo "=== 6j. Commit messages ==="
git log --format="%s" --reverse
# Should show 5 descriptive messages

echo "=== 6k. Backup still intact ==="
git log --oneline origin/pre-squash-backup | wc -l
# MUST be 148
```

**If ALL checks in Step 6 pass, proceed to Step 7. If ANY check fails, STOP and report.**

---

### Step 7: Clean Up Backup Branch

ONLY do this after Step 6 passes completely.

```bash
# Delete backup from remote
git push origin --delete pre-squash-backup

# Delete backup locally
git branch -d pre-squash-backup 2>/dev/null || git branch -D pre-squash-backup

# Verify no stale branches
git branch -a
# Should show only: * master and remotes/origin/master (plus remotes/origin/HEAD)

# Final state
echo ""
echo "========================================="
echo "  Git history squash complete"
echo "  5 commits on master"
echo "  v0.3.0 tag on HEAD"
echo "  No backup branches remaining"
echo "  All tests passing"
echo "========================================="
git log --oneline
```

---

## Emergency Rollback

If anything goes wrong at ANY point after Step 4, restore from the backup:

```bash
# Restore master from backup
git checkout master
git reset --hard origin/pre-squash-backup

# Force-push restored master
git push --force origin master

# Re-tag v0.3.0 at the original commit
git tag -d v0.3.0 2>/dev/null
git tag v0.3.0 f1c84be
git push origin v0.3.0 --force

# Verify restoration
git log --oneline | wc -l
# Should be 148 again
```

---

## Rules

- **NEVER skip a verification step.** Every checkpoint exists because something can go wrong there.
- **STOP on any failure.** Do not attempt to fix-and-continue. Report the failure.
- **The tree hash is the source of truth.** If the tree hashes match, the code is identical regardless of commit history. If they don't match, something went wrong.
- **Do NOT delete the backup branch until Step 6 passes completely.** The backup is your only rollback path.
- **Do NOT modify any code.** This is purely a git history operation. If you find yourself editing files, you've gone off-script.
- **Keep the commit author as-is** (whatever git config user.name/email is set to). Do not add Co-authored-by trailers to historical commits — that convention starts from Phase 4 forward.
- **The tag `v0.3.0` must end up on the final commit (HEAD).** Not on any intermediate commit. The tag previously pointed to `f1c84be` (commit 4 of 5 in the old history, now absorbed into commit 5). After the squash, it points to the new HEAD which contains the same tree.
