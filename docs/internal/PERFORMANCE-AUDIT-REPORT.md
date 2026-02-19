# KubeVigil Performance Optimization & Code Quality Audit

**Date:** 2026-02-18
**Platform:** darwin/arm64 (Apple M3 Ultra, 32 cores)
**Go Version:** 1.25+
**Codebase:** 24,878 LOC production / 51,259 LOC test (2.06:1 test ratio)

---

## Executive Summary

This audit established a comprehensive benchmark suite (38 benchmarks across 5 packages), profiled all hot paths with pprof, implemented 5 targeted optimizations, and audited godoc coverage. All optimizations were profile-driven and benchmark-verified.

**Key wins:**
- Scan engine: **42-51% faster**, **61-65% less memory**
- Workload checkers: **95.8% faster**, **90.9% less memory**
- Report generation: **10-22% faster**, **25.6% less memory**
- Fix planning: **29% faster**, **35% less memory**
- Zero regressions. Coverage stable at 93.8%.

---

## Phase A: Baseline Establishment

### Benchmark Suite Created

| Package | Benchmarks | File |
|---------|-----------|------|
| `internal/engine` | 7 | `bench_test.go` |
| `internal/checker` | 6 | `bench_test.go` |
| `internal/checker/workload` | 4 | `bench_test.go` |
| `internal/report` | 8 | `bench_test.go` |
| `internal/fix` | 14 | `bench_test.go` |
| **Total** | **39** | |

### Benchmark Fixtures

| Fixture | Lines | Resources |
|---------|-------|-----------|
| `test/benchdata/small.yaml` | 37 | 1 Deployment |
| `test/benchdata/medium.yaml` | 274 | ~10 mixed resources |
| `test/benchdata/large.yaml` | 1,598 | ~50 mixed resources |
| `test/benchdata/dir/` (40 files) | 1,159 | 40 individual manifests |

### Profiling Summary (pprof)

| Hot Path | Memory Share | Root Cause |
|----------|-------------|------------|
| `ExtractPodSpecs` | 68% of engine | JSON marshal/unmarshal repeated per checker |
| `extractFromUnstructured` | 51% of engine | `json.Marshal` + `json.Unmarshal` cycle |
| `ComputeSummary` | 26% of report | Multiple passes + full-slice `slices.Clone` |
| `computeLCS` | 15% of fix | 2D `[][]int` table allocation (m+2 slices) |
| `FilterFindings` | 4.4% of engine | `ExemptionKey` using `fmt.Sprintf` |

---

## Phase B: Issues Filed

| Tasks ID | Optimization | Priority |
|----------|-------------|----------|
| `KubeVigil-nk9y` | Cache ExtractPodSpecs results | P1 |
| `KubeVigil-07cf` | computeLCS flat table | P2 |
| `KubeVigil-w3xx` | Single-pass ComputeSummary | P2 |
| `KubeVigil-byqc` | ResourceCache.List() freeze | P2 |
| `KubeVigil-878a` | ExemptionKey string concat | P3 |
| `KubeVigil-dyht` | Code comments audit | P3 |

All issues closed.

---

## Phase C: Optimization Results (benchstat)

### 1. ExtractPodSpecs Caching (`KubeVigil-nk9y`)

**Technique:** `sync.Map` + `sync.Once` in `ResourceCache.CachedResult()`. PodSpec extraction runs once, all 25 workload checkers share the cached result.

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| ExtractPodSpecs (ns/op) | 47,579 | 38.56 | **-99.92%** |
| ExtractPodSpecs (B/op) | 40,780 | 48 | **-99.88%** |
| ExtractPodSpecs (allocs/op) | 468 | 2 | **-99.57%** |
| AllWorkloadCheckers (ns/op) | 539,780 | 22,950 | **-95.75%** |
| AllWorkloadCheckers (B/op) | 449,771 | 40,847 | **-90.92%** |
| AllWorkloadCheckers (allocs/op) | 5,038 | 370 | **-92.66%** |

**Files modified:** `internal/checker/resource_cache.go`, `internal/checker/workload/pod_spec.go`, `internal/engine/scanner.go`

### 2. ResourceCache.List() Freeze (`KubeVigil-byqc`)

**Technique:** `Freeze()` pre-computes flat slices after cache population. `List()` returns the frozen slice directly — zero allocation.

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| CacheListFrozen (ns/op) | N/A | 16.77 | New (was 134.4ns unfrozen) |
| CacheListFrozen (B/op) | N/A | 0 | New (was 168B unfrozen) |
| CacheListFrozen (allocs/op) | N/A | 0 | New (was 3 unfrozen) |

**Files modified:** `internal/checker/resource_cache.go`, `internal/engine/scanner.go`

### 3. Single-Pass ComputeSummary (`KubeVigil-w3xx`)

**Technique:** Consolidated 7 separate loops into one pass. Insertion-based top-5 extraction (no full copy+sort). Per-namespace `ClassifyNamespace` caching.

| Benchmark | Before (B/op) | After (B/op) | Change |
|-----------|--------------|-------------|--------|
| ReportText | 167,752 | 76,360 | **-54.47%** |
| ReportJSON | 336,179 | 237,030 | **-29.50%** |
| ReportSARIF | 289,254 | 194,150 | **-32.85%** |
| ReportJUnit | 347,750 | 256,307 | **-26.31%** |
| ReportMarkdown | 309,760 | 218,317 | **-29.53%** |
| ReportHTML | 724,480 | 622,694 | **-14.05%** |

**Files modified:** `internal/report/summary.go`

### 4. computeLCS Flat Table (`KubeVigil-07cf`)

**Technique:** Replaced `[][]int` (m+2 allocations) with a single flat `[]int` using row-major indexing.

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| DiffGeneration (ns/op) | 11,044 | 9,649 | **-12.63%** |
| DiffGeneration (B/op) | 27,156 | 26,419 | **-2.72%** |
| DiffGeneration (allocs/op) | 110 | 75 | **-31.82%** |

**Files modified:** `internal/fix/diff.go`

### 5. ExemptionKey String Concat (`KubeVigil-878a`)

**Technique:** Replaced `fmt.Sprintf("%s/%s/%s", ...)` with `namespace + "/" + kind + "/" + name`.

**Files modified:** `internal/config/exemptions.go`

### End-to-End Scan Impact

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| ScanManifest_AllChecks (ms) | 1.758 | 1.017 | **-42.15%** |
| ScanManifest_AllChecks (KB) | 2,882 | 1,015 | **-64.77%** |
| ScanManifest_AllChecks (allocs) | 31,504 | 8,651 | **-72.54%** |
| ScanManifest_LargeAllChecks (ms) | 7.603 | 3.761 | **-50.54%** |
| ScanManifest_LargeAllChecks (MB) | 12.178 | 4.724 | **-61.21%** |
| ScanManifest_LargeAllChecks (allocs) | 134,152 | 45,050 | **-66.42%** |
| FixerPlan (ms) | 3.247 | 2.307 | **-28.94%** |
| FixerPlan (MB) | 5.236 | 3.383 | **-35.38%** |
| FixerPlan (allocs) | 38,510 | 15,300 | **-60.26%** |

---

## Phase D: Code Comments Audit

| Finding | Count | Fix |
|---------|-------|-----|
| Missing package doc (`internal/k8s`) | 1 | Added `// Package k8s ...` |
| Missing method godoc (cluster checkers) | 60 | Added standard comments to all 10 checkers |
| Dead code (`computePostureScore`, `computeTierPostureScore`) | 2 functions | Removed |
| `interface{}` -> `any` modernization | 5 occurrences | Updated |

---

## Phase E: Quality Gates

### Coverage

| Metric | Pre-Audit | Post-Audit | Delta |
|--------|-----------|------------|-------|
| Overall coverage | 93.8% | 93.8% | 0% |
| Test LOC | 50,168 | 51,259 | +1,091 |
| Production LOC | 25,306 | 24,878 | -428 |

Coverage held stable. Production LOC decreased due to dead code removal.

### Tests

```
ok  github.com/stribog-cloud/kubevigil/cmd/kubevigil
ok  github.com/stribog-cloud/kubevigil/internal/checker
ok  github.com/stribog-cloud/kubevigil/internal/checker/cloud
ok  github.com/stribog-cloud/kubevigil/internal/checker/cluster
ok  github.com/stribog-cloud/kubevigil/internal/checker/crd
ok  github.com/stribog-cloud/kubevigil/internal/checker/image
ok  github.com/stribog-cloud/kubevigil/internal/checker/network
ok  github.com/stribog-cloud/kubevigil/internal/checker/psa
ok  github.com/stribog-cloud/kubevigil/internal/checker/rbac
ok  github.com/stribog-cloud/kubevigil/internal/checker/scheduling
ok  github.com/stribog-cloud/kubevigil/internal/checker/secrets
ok  github.com/stribog-cloud/kubevigil/internal/checker/storage
ok  github.com/stribog-cloud/kubevigil/internal/checker/supply_chain
ok  github.com/stribog-cloud/kubevigil/internal/checker/workload
ok  github.com/stribog-cloud/kubevigil/internal/config
ok  github.com/stribog-cloud/kubevigil/internal/engine
ok  github.com/stribog-cloud/kubevigil/internal/fix
ok  github.com/stribog-cloud/kubevigil/internal/frameworks
ok  github.com/stribog-cloud/kubevigil/internal/k8s
ok  github.com/stribog-cloud/kubevigil/internal/report
ok  github.com/stribog-cloud/kubevigil/internal/version
ok  github.com/stribog-cloud/kubevigil/test/helpers
ok  github.com/stribog-cloud/kubevigil/test/integration
```

All 23 packages pass. Zero regressions.

### Lint

`go vet ./...` passes clean. No new warnings introduced.

---

## Artifacts

| File | Purpose |
|------|---------|
| `bench-baseline.txt` | Pre-optimization benchmark data (5 runs) |
| `bench-after.txt` | Post-optimization benchmark data (5 runs) |
| `coverage-pre-audit.out` | Pre-audit coverage profile |
| `test/benchdata/` | Benchmark fixtures (small, medium, large, dir/) |
| `internal/*/bench_test.go` | 39 benchmarks across 5 packages |
