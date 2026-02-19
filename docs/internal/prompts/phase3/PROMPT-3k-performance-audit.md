# PROMPT — Performance Optimization & Code Quality Audit

> **Role:** You are an independent performance auditor. Your mandate is to identify, implement, and **quantify** performance improvements across KubeVigil's entire codebase — scanning engine, checker framework, auto-fix engine, report generators, and CLI. Every optimization must produce a measurable before/after benchmark result. You are also tasked with elevating code-level documentation (comments) to production-grade quality.

---

## Pre-Flight

**Read these files first:**

- `CLAUDE.md` — Project identity, phases, architecture overview
- `AGENTS.md` — Tasks workflow, session completion rules

**Then explore the performance landscape:**

```bash
# Understand the codebase scale
find . -name "*.go" -not -name "*_test.go" -not -path "./.git/*" | xargs wc -l | tail -1
find . -name "*_test.go" -not -path "./.git/*" | xargs wc -l | tail -1

# Verify zero existing benchmarks
grep -rn "func Benchmark" --include="*.go"

# Understand the hot path: scan → check → report
cat internal/engine/scanner.go
cat internal/engine/manifest_parser.go
cat internal/checker/resource_cache.go

# Understand checker helper patterns
grep -rn "ExtractPodSpecs\|extractPodSpec" internal/ --include="*.go" | grep -v test
grep -rn "\.List(" internal/checker/ --include="*.go" | grep -v test | wc -l

# Understand report generation
wc -l internal/report/*.go | grep -v test | sort -rn

# Understand fix engine
wc -l internal/fix/*.go | grep -v test | sort -rn
```

**Ground rules:**

- Every optimization must have a benchmark proving the improvement.
- Tests should NOT be modified unless a code change requires it (e.g., new function signature).
- Coverage must not drop. Measure before and after.
- TDD: write the benchmark first, observe the baseline, then optimize, then re-measure.
- All work tracked in Tasks — file issues before writing code.
- Follow AGENTS.md for session completion (commit, push).

---

## Phase A: Establish Baselines

### A1. Benchmark Suite Foundation

Create `internal/bench_test.go` (or per-package `*_bench_test.go` files) with benchmarks covering every performance-critical path. These benchmarks are the **source of truth** for measuring gains.

**Required benchmarks (minimum):**

#### Scan Engine
```
BenchmarkParseFile_Small          — single YAML, 1 resource
BenchmarkParseFile_Large          — multi-doc YAML, 50+ resources
BenchmarkParseDir                 — directory with 20+ YAML files
BenchmarkParseBytes_MultiDoc      — raw byte parsing, multi-document
BenchmarkScanManifest_AllChecks   — full scan pipeline with all 110 checks
BenchmarkScanManifest_SingleCheck — single check in isolation
```

#### Resource Cache
```
BenchmarkCacheAdd                 — inserting resources
BenchmarkCacheList                — listing all resources for a GVR
BenchmarkCacheListNamespaced      — listing resources by namespace
BenchmarkCacheLen                 — counting total resources
```

#### Checker Framework
```
BenchmarkExtractPodSpecs          — the shared PodSpec extraction helper
BenchmarkCheckerRun_Workload      — a representative workload checker
BenchmarkCheckerRun_RBAC          — a representative RBAC checker
BenchmarkCheckerRun_Network       — a representative network checker
BenchmarkAllCheckersSequential    — all 110 checks, no concurrency
BenchmarkAllCheckersConcurrent    — all 110 checks, with errgroup
```

#### Report Generation
```
BenchmarkReportText               — text output for ~100 findings
BenchmarkReportJSON               — JSON output for ~100 findings
BenchmarkReportHTML               — HTML output for ~100 findings
BenchmarkReportSARIF              — SARIF output for ~100 findings
BenchmarkReportMarkdown           — Markdown output for ~100 findings
BenchmarkReportCSV                — CSV output for ~100 findings
```

#### Fix Engine
```
BenchmarkYAMLParse_SingleDoc      — YAML document parsing
BenchmarkYAMLParse_MultiDoc       — multi-document YAML parsing
BenchmarkYAMLSerialize            — document serialization
BenchmarkFindNode                 — YAML node lookup by path
BenchmarkSetNode                  — YAML node mutation
BenchmarkFixerPlan                — building a fix plan for 20 findings
BenchmarkFixerApply               — applying patches to a YAML file
BenchmarkDiffGeneration           — generating unified diff output
BenchmarkKustomizeGen             — Kustomize overlay generation
```

#### CLI / End-to-End
```
BenchmarkCLIScan_SmallDir         — full CLI scan of small fixture directory
BenchmarkCLIScan_LargeDir         — full CLI scan of large fixture directory
BenchmarkCLIFix_DryRun            — fix dry-run over a directory
```

**Benchmark fixture strategy:**

All benchmarks run against **local YAML fixtures only** — no live Kubernetes cluster needed. KubeVigil's architecture cleanly separates data fetching from processing. The `ResourceCache` abstraction means checkers receive the same `[]unstructured.Unstructured` objects whether data came from YAML files or a live API server. Once the cache is populated, everything downstream (checkers, reports, fixes) is identical regardless of source.

Live cluster benchmarks would measure Kubernetes API server response time, not KubeVigil's code — those numbers vary with cluster size, network conditions, and machine load. Not useful. All the optimizable hot paths (parsing, cache operations, checker logic, report rendering, YAML patching) are exercised through fixture-based benchmarks.

Create `test/benchdata/` with purpose-built fixtures:
- `small.yaml` — single Deployment, ~30 lines
- `medium.yaml` — 10 resources (mix of kinds), ~300 lines
- `large.yaml` — 50+ resources, multi-document, ~1500 lines
- `dir/` — 20 separate YAML files, mix of resource types
- `findings.json` — serialized ScanResult with ~100 findings for report benchmarks

For checker benchmarks, populate a `ResourceCache` from fixture YAML in the benchmark setup function (outside the `b.N` loop), then benchmark only the checker's `Run()` method. This isolates checker logic from file I/O.

These fixtures must be deterministic (no randomness) so benchmarks are reproducible. Do NOT spin up Kind or any other Kubernetes cluster for benchmarking.

### A2. Record Baselines

Run every benchmark and capture baseline results:

```bash
go test -bench=. -benchmem -count=5 -timeout=300s ./... 2>&1 | tee bench-baseline.txt
```

Save `bench-baseline.txt` in the project root (add to `.gitignore`). This is the "before" snapshot.

Also record:
```bash
go test -coverprofile=coverage-pre-audit.out ./...
go tool cover -func=coverage-pre-audit.out | tail -1
```

### A3. CPU and Memory Profiling

Run targeted profiles on the hot paths:

```bash
# CPU profile for a full scan
go test -cpuprofile=cpu-scan.prof -bench=BenchmarkScanManifest_AllChecks ./internal/engine/
go tool pprof -top cpu-scan.prof

# Memory profile for report generation
go test -memprofile=mem-report.prof -bench=BenchmarkReportHTML ./internal/report/
go tool pprof -top mem-report.prof

# CPU profile for fix engine
go test -cpuprofile=cpu-fix.prof -bench=BenchmarkFixerApply ./internal/fix/
go tool pprof -top cpu-fix.prof
```

Identify the top 10 CPU consumers and top 10 memory allocators. These drive your optimization priorities.

---

## Phase B: File Tasks Issues

Based on profiling results from Phase A, file issues for every optimization. Group logically:

**Likely issues (file after confirming with profiling data):**

| Issue Title | Likely Scope |
|---|---|
| `perf-cache-list-allocation` | ResourceCache.List() allocates a new slice on every call (53 callers) |
| `perf-podspec-extraction-caching` | ExtractPodSpecs called repeatedly by independent checkers for the same resources |
| `perf-yaml-parsing-multifile` | Directory parsing is sequential file-by-file; parallelize |
| `perf-html-report-generation` | HTML report is 2232 lines of Go with string building; profile and optimize |
| `perf-unstructured-nested-calls` | 58 unstructured.Nested* calls in checkers; consider typed extraction |
| `perf-finding-sort-allocation` | Finding slices sorted and copied repeatedly through the pipeline |
| `perf-scanner-concurrency-tuning` | Validate errgroup concurrency limit is optimal |
| `perf-fix-yaml-roundtrip` | YAML parse → modify → serialize path; measure and optimize |
| `perf-report-string-allocation` | String building patterns across report generators |
| `perf-severity-override-lookup` | applySeverityOverrides iterates config per finding; use map lookup |
| `perf-gvr-lookup-manifest` | GVRForKind does string concatenation + map lookup; pre-compute keys |
| `perf-regex-compilation` | Verify all regex compiled at init time, not per-call |
| `code-comments-packages` | Package-level doc comments missing from most packages |
| `code-comments-exported` | Exported functions/types missing doc comments |
| `code-comments-hot-paths` | Inline comments explaining non-obvious performance decisions |

**Important:** These are hypotheses. File issues AFTER Phase A profiling confirms they are real bottlenecks, not before. Do not optimize what doesn't show up in profiles.

---

## Phase C: Performance Optimizations

### C1. Optimization Methodology — TDD

For EVERY optimization, follow this exact workflow:

1. **Write the benchmark** (if not already in Phase A baseline)
2. **Run baseline:** `go test -bench=BenchmarkXxx -benchmem -count=5`
3. **Record baseline** numbers (ns/op, B/op, allocs/op)
4. **Implement the optimization**
5. **Run the SAME tests** to verify nothing breaks
6. **Run the SAME benchmark:** `go test -bench=BenchmarkXxx -benchmem -count=5`
7. **Record optimized** numbers
8. **Calculate improvement:** `benchstat baseline.txt optimized.txt` (if benchstat available) or manual comparison
9. **Reject the change** if improvement is <5% — not worth the complexity
10. **Run full test suite** to verify zero regressions: `go test ./...`
11. **Check coverage:** ensure it hasn't dropped

### C2. Known Optimization Targets

These are the likely optimization areas based on code review. **Only pursue them if profiling confirms they are hot paths:**

#### ResourceCache.List() Allocation (HIGH PRIORITY)

**Problem:** `List()` creates a new `[]unstructured.Unstructured` slice on every call by iterating all namespaces and appending. Called 53 times from checker code — once per checker per GVR.

**Potential fix:** Pre-compute the merged list when the cache is finalized (after population, before checkers run). Add a `Freeze()` method that builds the merged lists once. Subsequent `List()` calls return the pre-computed slice (no allocation).

**Constraint:** Must be backwards-compatible. Existing `List()` signature unchanged. `Freeze()` is optional — cache works without it, just slower.

#### ExtractPodSpecs Redundancy (HIGH PRIORITY)

**Problem:** Multiple checkers independently call `workload.ExtractPodSpecs(cache)` which iterates all workload resources and extracts PodSpecs. If 15 workload-category checkers each call this, the same extraction happens 15 times.

**Potential fix:** Compute `PodSpecs` once during cache freeze and store as a pre-computed field. Or use a `sync.Once`-based lazy cache inside ResourceCache.

**Constraint:** Must not change the Checker interface. Optimization should be transparent.

#### Directory Parsing Parallelization (MEDIUM PRIORITY)

**Problem:** `ParseDir()` walks files sequentially — reads each file, parses it, adds to cache.

**Potential fix:** Use a worker pool (errgroup with limit) to parse files concurrently. File I/O and YAML parsing are independent per file. Cache.Add() is already mutex-protected.

**Constraint:** Error collection must remain deterministic (sorted by file path). Benchmark on both SSD and spinning disk if possible.

#### Report Generator Optimization (MEDIUM PRIORITY)

**Problem:** HTML report is the largest generator (2232 lines). Profile to find if string building, template rendering, or data iteration is the bottleneck.

**Potential fix:** Depends on profiling. Likely candidates:
- Pre-size strings.Builder based on finding count
- Reduce fmt.Sprintf calls in hot loops (use WriteString)
- Cache repeated CSS/JS in a package-level constant (verify it isn't already)

#### Severity Override Map Lookup (LOW PRIORITY)

**Problem:** `applySeverityOverrides()` may do config lookup per finding. If config uses a list, this is O(n*m).

**Potential fix:** Build a `map[checkID]severity` at scan start. O(1) lookup per finding.

#### GVRForKind String Concatenation (LOW PRIORITY)

**Problem:** `GVRForKind()` does `apiVersion + "/" + kind` on every call. In manifest parsing, this is called per resource.

**Potential fix:** Accept pre-concatenated key, or use a struct key instead of string concatenation.

### C3. Parallelization Strategy

Use **sub-agents** for independent optimization work:

| Agent | Scope | Dependencies |
|-------|-------|-------------|
| Agent 1 | Benchmark suite creation + baseline recording (Phase A) | None — start first |
| Agent 2 | ResourceCache optimizations (List, Freeze, PodSpec caching) | Needs baseline from Agent 1 |
| Agent 3 | Manifest parser parallelization | Independent |
| Agent 4 | Report generator optimization (all formats) | Needs benchmarks from Agent 1 |
| Agent 5 | Fix engine YAML roundtrip optimization | Independent |
| Agent 6 | Code comments (Phase D) | Independent — can run in parallel with all others |
| Agent 7 | Final measurement, benchstat comparison, summary report | LAST — runs after all optimizations |

Use **agent teams** when:
- Cache optimization (Agent 2) affects checker behavior — verify with checker benchmarks
- Report optimization needs the same test fixtures as scan benchmarks

---

## Phase D: Code Comments Audit

### D1. Scope

Add or improve comments across ALL non-test Go files. This does NOT change behavior — only adds documentation.

### D2. Package-Level Comments

Every package needs a `doc.go` or a comment at the top of its primary file explaining:
- What the package does
- How it fits into the overall architecture
- Key types and entry points

**Packages currently missing package-level doc comments (non-exhaustive — do a full scan):**
- `internal/checker/` and all sub-packages (cloud, cluster, crd, image, network, psa, rbac, scheduling, secrets, storage, supply_chain, workload)
- `internal/engine/`
- `internal/fix/`
- `internal/report/`
- `internal/config/`
- `internal/frameworks/`
- `cmd/kubevigil/`

### D3. Exported Type and Function Comments

Every exported type, function, method, and constant must have a Go-doc-compliant comment. The comment must:
- Start with the name of the identifier
- Describe WHAT it does (not HOW — the code shows how)
- Note any important constraints, thread-safety, or error behavior

**Example (good):**
```go
// ParsePath parses a file or directory at the given path into a ResourceCache.
// If the path is a directory, it recursively walks all YAML files.
// Returns the populated cache and any non-fatal errors encountered.
func ParsePath(path string) (*checker.ResourceCache, []error) {
```

**Example (bad):**
```go
// This function parses stuff
func ParsePath(path string) (*checker.ResourceCache, []error) {
```

### D4. Inline Comments for Non-Obvious Code

Add inline comments ONLY where the code is non-obvious:
- Performance-critical sections (explain WHY a certain approach was chosen)
- Concurrency patterns (explain the synchronization model)
- YAML manipulation (explain the node tree navigation)
- Safety checks in the fix engine (explain the threat model)

Do NOT add trivial comments like `// increment counter` next to `count++`.

### D5. Comment Rules

- DO NOT change any code behavior. Comments only.
- DO NOT modify test files for comments (tests are out of scope).
- DO NOT remove existing accurate comments.
- FIX any existing comments that are incorrect or misleading.
- USE Go documentation conventions: https://go.dev/doc/comment
- Coverage MUST remain unchanged (comments don't affect coverage, but verify).

---

## Phase E: Final Measurement & Summary Report

### E1. Run Complete Benchmark Suite

```bash
go test -bench=. -benchmem -count=5 -timeout=300s ./... 2>&1 | tee bench-optimized.txt
```

### E2. Compare Results

If `benchstat` is available:
```bash
go install golang.org/x/perf/cmd/benchstat@latest
benchstat bench-baseline.txt bench-optimized.txt
```

If not, manually compare each benchmark: baseline vs optimized.

### E3. Verify Coverage

```bash
go test -coverprofile=coverage-post-audit.out ./...
go tool cover -func=coverage-post-audit.out | tail -1
```

Coverage must be ≥ the pre-audit number.

### E4. Generate Summary Report

Create `docs/internal/PERFORMANCE-AUDIT-REPORT.md` with:

```markdown
# KubeVigil Performance Audit Report

**Date:** [date]
**Auditor:** Claude Opus 4.6 (Independent Audit)
**Scope:** Full codebase — Phase 1, 2, 3

## Executive Summary

[2-3 sentences: what was done, headline improvement numbers]

## Coverage

| Metric | Pre-Audit | Post-Audit | Delta |
|--------|-----------|------------|-------|
| Total coverage | X% | Y% | +/-Z% |

## Benchmark Results

### Scan Engine

| Benchmark | Baseline (ns/op) | Optimized (ns/op) | Improvement | Baseline (B/op) | Optimized (B/op) | Memory Improvement |
|-----------|------------------|--------------------|-------------|-----------------|-------------------|--------------------|
| ParseFile_Small | ... | ... | ...% | ... | ... | ...% |
| ParseFile_Large | ... | ... | ...% | ... | ... | ...% |
| ScanManifest_AllChecks | ... | ... | ...% | ... | ... | ...% |

### Resource Cache

| Benchmark | Baseline | Optimized | Improvement | Baseline Allocs | Optimized Allocs | Alloc Reduction |
|-----------|----------|-----------|-------------|----------------|------------------|----|
| ... | ... | ... | ... | ... | ... | ... |

### Checker Framework

[same table format]

### Report Generation

[same table format]

### Fix Engine

[same table format]

### CLI End-to-End

[same table format]

## Optimizations Applied

### 1. [Optimization Name]
- **Issue:** [Tasks issue ID]
- **Problem:** [1-2 sentences]
- **Solution:** [1-2 sentences]
- **Impact:** X% faster, Y% less memory
- **Files changed:** [list]

### 2. [Next optimization]
...

## Optimizations Considered But Rejected

### [Name]
- **Reason:** [profiling showed <5% impact / added too much complexity / etc.]

## Code Comments Added

- Package-level doc comments: X packages
- Exported function/type comments: Y added/improved
- Inline comments: Z added for non-obvious code

## Tasks Issues

| Issue ID | Title | Status |
|----------|-------|--------|
| ... | ... | Closed ✅ |
```

---

## Completion Criteria

- [ ] Benchmark suite covers all performance-critical paths (minimum 30 benchmarks)
- [ ] Benchmark fixtures created in `test/benchdata/`
- [ ] Baseline recorded in `bench-baseline.txt`
- [ ] CPU and memory profiles analyzed for top bottlenecks
- [ ] Every optimization has before/after benchmark proof
- [ ] No optimization accepted with <5% improvement
- [ ] Full test suite passes: `go test ./...`
- [ ] Coverage has not dropped (before ≥ after)
- [ ] Every exported function/type has a Go-doc comment
- [ ] Every package has a package-level doc comment
- [ ] Performance audit report generated with all tables populated
- [ ] Tasks clean: all audit issues closed
- [ ] Git committed and pushed per AGENTS.md protocol

---

## Rules

- **Profile first, optimize second.** Never optimize based on intuition. Let `pprof` tell you where the time is spent.
- **Benchmarks are non-negotiable.** No benchmark = no optimization. Every claim must be provable.
- **Reject marginal gains.** If an optimization adds complexity but yields <5% improvement, reject it and document why.
- **Do not break existing tests.** If a test needs changing, it's because the API changed — document why.
- **Coverage is a floor, not a ceiling.** It must not drop. New benchmark test files will likely increase it.
- **Comments are code.** Treat them with the same quality bar as the code itself. Inaccurate comments are worse than no comments.
- **Quantify everything.** The final report must have numbers, not adjectives. "Faster" is not acceptable. "37% faster (142ns → 89ns)" is.
- **File before fixing.** All Tasks issues filed before optimization work begins.
- **Use sub-agents aggressively.** The benchmark suite, cache optimization, parser optimization, report optimization, fix optimization, and comment audit are all independent work streams.
- **Land the plane.** Follow AGENTS.md. Push everything. The performance audit report is the final deliverable.
